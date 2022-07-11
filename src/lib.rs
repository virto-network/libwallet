// #![feature(result_option_inspect)]
#![cfg_attr(not(feature = "std"), no_std)]
//! With `libwallet` you can build crypto currency wallets that
//! manage private keys of different kinds saved in a secure storage.
#[cfg(not(any(feature = "sr25519")))]
compile_error!("Enable at least one type of signature algorithm");

mod account;
mod key_pair;
#[cfg(feature = "osvault")]
mod osvault;
#[cfg(feature = "simple")]
mod simple;
#[cfg(feature = "substrate")]
mod substrate_ext;

use arrayvec::ArrayVec;
use core::{convert::TryInto, future::Future};
use key_pair::any::AnySignature;

#[cfg(feature = "mnemonic")]
use mnemonic;

pub use account::Account;
pub use key_pair::*;
#[cfg(feature = "mnemonic")]
pub use mnemonic::{Language, Mnemonic};
#[cfg(feature = "osvault")]
pub use osvault::OSVault;
#[cfg(feature = "simple")]
pub use simple::SimpleVault;

// pub type Result<T> = core::result::Result<T, Error>;

type Message = ArrayVec<u8, { u8::MAX as usize }>;

/// Abstration for storage of private keys that are protected behind some credentials.
pub trait Vault {
    type Credentials;
    type AuthDone: Future<Output = core::result::Result<(), Self::Error>>;
    type Error;

    fn unlock(&mut self, cred: Self::Credentials) -> Self::AuthDone;

    fn get_root(&self) -> Option<&RootAccount>;
}

/// The root account is a container of the key pairs stored in the vault and cannot be used directly,
/// we always derive new key pairs from it to create and use accounts with the wallet.
#[derive(Debug)]
pub struct RootAccount {
    #[cfg(feature = "substrate")]
    sub: key_pair::sr25519::Pair,
}

impl RootAccount {
    fn from_bytes(seed: &[u8]) -> Self {
        RootAccount {
            #[cfg(feature = "substrate")]
            sub: <key_pair::sr25519::Pair as crate::Pair>::from_bytes(seed),
        }
    }

    #[cfg(feature = "rand")]
    fn generate<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let seed = util::random_bytes::<_, 32>(rng);
        Self::from_bytes(&seed)
    }

    #[cfg(feature = "rand")]
    fn generate_with_phrase<R>(rng: &mut R, lang: Language) -> (Self, Mnemonic)
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let seed = util::random_bytes::<_, 32>(rng);
        let phrase = mnemonic::Mnemonic::from_entropy_in(lang, seed.as_ref()).expect("seed valid");
        (Self::from_bytes(&seed), phrase)
    }
}

impl<'a> Derive for &'a RootAccount {
    type Pair = any::Pair;

    fn derive(&self, _path: &str) -> Self::Pair
    where
        Self: Sized,
    {
        todo!()
    }
}

/// Wallet is the main interface to interact with blockchain accounts. Before being able
/// to use the accounts for signing for example the wallet needs to be unlocked with the
/// set of credentials supported by the underlying vault.  
///
/// Wallets have the concept of a `default account` that is used to sign messages
/// when no account is specified. Messages can be queued to be signed later in bulk.
#[derive(Debug)]
pub struct Wallet<V, const A: usize = 5, const M: usize = A> {
    vault: V,
    default_account: Account,
    accounts: ArrayVec<Account, A>,
    pending_sign: ArrayVec<(Message, Option<u8>), M>, // message -> account index or default
}

impl<'a, V, const A: usize, const M: usize> Wallet<V, A, M>
where
    V: Vault,
{
    pub fn new(vault: V) -> Self {
        Wallet {
            vault,
            default_account: Account::new(None),
            accounts: ArrayVec::new_const(),
            pending_sign: ArrayVec::new(),
        }
    }

    pub fn default_account(&self) -> &Account {
        &self.default_account
    }

    /// A locked wallet uses its vault to retrive the key pair used to sign transactions.
    /// ```
    /// # use libwallet::{Wallet, Error, SimpleVault, sr25519};
    /// # use std::convert::TryInto;
    /// # #[async_std::main] async fn main() -> Result<(), Error> {
    /// let vault: SimpleVault<sr25519::Pair> = "//Alice".into();
    /// let mut wallet = Wallet::from(vault);
    /// if wallet.is_locked() {
    ///     wallet = wallet.unlock(()).await?;
    /// }
    /// # assert_eq!(wallet.is_locked(), false);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn unlock(&mut self, credentials: V::Credentials) -> Result<(), Error> {
        if self.is_locked() {
            self.vault
                .unlock(credentials)
                .await
                .map_err(|_| Error::InvalidCredentials)?;
            self.default_account.unlock(self.vault.get_root().unwrap());
        }
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.vault.get_root().is_none()
    }

    /// Sign a message with the default account and return the 512bit signature.
    /// ```
    /// # use libwallet::{Wallet, SimpleVault, sr25519, Result};
    /// # #[async_std::main] async fn main() -> Result<()> {
    ///
    /// let wallet = Wallet::new(SimpleVault::<sr25519::Pair>::new()).unlock(()).await?;
    /// let signature = wallet.sign(&[0x01, 0x02, 0x03]);
    /// # assert!(signature.is_ok());
    /// # Ok(()) }
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<impl Signature, Error> {
        Ok(self.default_account().sign_msg(message))
    }

    /// Save data to be signed later by root account
    /// ```
    /// # use libwallet::{Wallet, SimpleVault, sr25519, Result};
    /// # #[async_std::main] async fn main() -> Result<()> {
    ///
    /// let mut wallet = Wallet::new(SimpleVault::<sr25519::Pair>::new()).unlock(()).await?;
    /// let res = wallet.sign_later(&[0x01, 0x02, 0x03]);
    /// assert!(res.is_ok());
    /// # Ok(()) }
    /// ```
    pub fn sign_later<'b: 'a, T>(&'b mut self, message: T)
    where
        T: AsRef<[u8]>,
    {
        let msg = message.as_ref()[..self.pending_sign.capacity()]
            .try_into()
            .unwrap();
        self.pending_sign.push((msg, None));
    }

    /// Try to sign all messages in the queue of an account
    /// Returns signed transactions
    /// ```
    /// # use libwallet::{Wallet, SimpleVault, sr25519, Result};
    /// # #[async_std::main] async fn main() -> Result<()> {
    ///
    /// let mut wallet = Wallet::new(SimpleVault::<sr25519::Pair>::new()).unlock(()).await?;
    /// wallet.sign_later(&[0x01, 0x02, 0x03]);
    /// wallet.sign_later(&[0x01, 0x02]);
    /// wallet.sign_pending("ROOT");
    /// let res = wallet.get_pending("ROOT").collect::<Vec<_>>();
    /// assert!(res.is_empty());
    /// # Ok(()) }
    /// ```
    pub fn sign_pending(&mut self) -> [AnySignature; M] {
        let mut signatures = ArrayVec::new();
        for (msg, a) in self.pending_sign.take() {
            let account = a
                .map(|idx| self.account(idx))
                .unwrap_or_else(|| self.default_account());
            signatures.push(account.sign_msg(&msg));
        }
        signatures.into_inner().expect("signatures")
    }

    /// Iteratate over the messages with pending signature of all the accounts.
    /// It panics if the wallet is locked.
    ///
    /// ```
    /// # use libwallet::{Wallet, SimpleVault, sr25519, Result};
    /// # #[async_std::main] async fn main() -> Result<()> {
    ///
    /// let mut wallet = Wallet::new(SimpleVault::<sr25519::Pair>::new()).unlock(()).await?;
    /// wallet.sign_later(&[0x01, 0x02, 0x03]);
    /// wallet.sign_later(&[0x01, 0x02]);
    /// let res = wallet.get_pending("ROOT").collect::<Vec<_>>();
    /// assert_eq!(vec![vec![0x01, 0x02, 0x03], vec![0x01, 0x02]], res);
    /// # Ok(()) }
    /// ```
    pub fn get_pending(&self) -> impl Iterator<Item = &[u8]> {
        self.pending_sign.iter().map(|(msg, _)| msg.as_ref())
    }

    #[cfg(feature = "subaccounts")]
    pub fn new_account(&mut self, name: &str, derivation_path: &str) -> Result<&Account<V::Pair>> {
        let root = self.root_account()?;
        let subaccount = root
            .derive_subaccount(name, derivation_path)
            .ok_or(Error::DeriveError)?;
        self.subaccounts.insert(name.to_string(), subaccount);
        Ok(self.subaccounts.get(name).unwrap())
    }

    fn account(&self, idx: u8) -> &Account {
        &self.accounts[idx as usize]
    }
}

// Represents the blockchain network in use by an account
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Network {
    // For substrate based blockchains commonly formatted as SS58
    // that are distinguished by their address prefix. 42 is the generic prefix.
    #[cfg(feature = "substrate")]
    Substrate(u16),
    // Space for future supported networks(e.g. ethereum, bitcoin)
    _Missing,
}

impl Default for Network {
    fn default() -> Self {
        #[cfg(feature = "substrate")]
        let net = Network::Substrate(42);
        #[cfg(not(feature = "substrate"))]
        let net = Network::_Missing;
        net
    }
}

impl core::fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            #[cfg(feature = "substrate")]
            Self::Substrate(_) => write!(f, "substrate"),
            _ => write!(f, ""),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Locked,
    InvalidCredentials,
    DeriveError,
    #[cfg(feature = "mnemonic")]
    InvalidPhrase,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Locked => write!(f, "Locked"),
            Error::InvalidCredentials => write!(f, "Invalid credentials"),
            Error::DeriveError => write!(f, "Cannot derive"),
            #[cfg(feature = "mnemonic")]
            Error::InvalidPhrase => write!(f, "Invalid phrase"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "mnemonic")]
impl From<mnemonic::Error> for Error {
    fn from(_: mnemonic::Error) -> Self {
        Error::InvalidPhrase
    }
}

mod util {
    #[cfg(feature = "rand")]
    pub fn random_bytes<R, const S: usize>(rng: &mut R) -> [u8; S]
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let mut bytes = [0u8; S];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}
