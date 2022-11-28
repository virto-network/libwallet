use super::storage::{MatrixCredentials, MatrixError, MatrixStorage, MxId};
use crate::{key_pair, RootAccount, Vault};

pub struct MatrixUserCreds<'a> {
    pub mxid: MxId<'a>,
    pub token: String,
}

pub struct Matrix<'a> {
    pub creds: MatrixUserCreds<'a>,
}

impl<'a> Matrix<'a> {
    pub fn new(creds: MatrixUserCreds) -> Matrix {
        Matrix { creds }
    }
}

const SECRET_NAME: &str = "id-seed";

impl<'a> Vault for Matrix<'a> {
    type Credentials = MatrixCredentials;
    type Error = MatrixError;

    async fn unlock<T>(
        &mut self,
        creds: &Self::Credentials,
        mut cb: impl FnMut(&RootAccount) -> T,
    ) -> Result<T, Self::Error> {
        let storage = MatrixStorage::new(&self.creds.mxid, &self.creds.token).await?;

        let stored_secret = storage.get_secret_from_storage(SECRET_NAME, creds).await;

        match stored_secret {
            Ok(Some(seed)) => Ok(cb(&RootAccount::from_bytes(&seed))),
            Ok(None) => {
                let key_pair = key_pair::sr25519::Pair::generate();
                let bytes = key_pair.secret.to_bytes();
                storage
                    .save_secret_in_storage(SECRET_NAME, &bytes, creds)
                    .await
                    .unwrap();
                Ok(cb(&RootAccount::from_bytes(&bytes)))
            }
            Err(err) => Err(err),
        }
    }
}
