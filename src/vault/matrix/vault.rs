use super::storage::{MatrixCredentials, MatrixError, MatrixStorage, MxId};
use crate::{key_pair, RootAccount, Vault};

pub struct Matrix<'a> {
    pub mxid: MxId<'a>,
    pub token: String,
}

impl<'a> Matrix<'a> {
    pub fn new(id: impl Into<MxId<'a>>, token: String) -> Matrix<'a> {
        Matrix {
            mxid: id.into(),
            token,
        }
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
        let storage = MatrixStorage::new(&self.mxid, &self.token).await?;
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
