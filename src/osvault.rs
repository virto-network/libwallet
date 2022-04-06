use crate::{async_trait, Box, Pair, Result, Vault, Error};

use keyring;


pub struct OSVault<P: Pair> {
    entry: keyring::Entry,
    seed: Option<P::Seed>,
}

impl<P: Pair> OSVault<P> {
    // Retrieve key saved in OS with given name.
    // If seed received, save this seed as password in the OS.
    pub fn new(name: &str, seed: Option<&str>) -> Self {
        let entry = keyring::Entry::new("wallet", &name);
        seed.map(|s| entry.set_password(s));
        OSVault {
            entry,
            seed: None//seed.map(|s| P::from_string_with_seed(s, None)),
        }
    }
}

#[async_trait(?Send)]
impl<P: Pair> Vault for OSVault<P> {
    type Pair = P;

    async fn unlock(&mut self, _: ()) -> Result<P> {
        // get seed from entry
        match self.entry.get_password() {
            Ok(s) => match P::from_phrase(&s, None) {
                Ok((pair, seed)) => {
                    self.seed = Some(seed);
                    Ok(pair)
                },
                Err(_) => Err(Error::InvalidPhrase),
            },
            Err(_) => Err(Error::InvalidPhrase),
        }
    }
}

