use crate::{Account, Vault, Wallet};
use codec::Encode;
use sp_core::crypto::CryptoType;

trait SubstrateExt {
    fn sign_extrinsic<T: Encode>(&self, extrinsic: T) -> Result<(), ()>;
}

impl<V: Vault> SubstrateExt for Wallet<V> {
    fn sign_extrinsic<T: Encode>(&self, extrinsic: T) -> Result<(), ()> {
        self.root_account()?.sign_extrinsic(extrinsic)
    }
}

impl<T> SubstrateExt for Account<T> {
    fn sign_extrinsic(&self, _extrinsic: &[u8]) -> Result<(), ()> {
        todo!()
    }
}

//impl SubstrateExt for Account {}
