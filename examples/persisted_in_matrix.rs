use libwallet::{self, vault::Matrix, vault::MatrixCredentials, vault::MatrixUserCreds};
use std::{env, error::Error};

type Wallet<'a> = libwallet::Wallet<Matrix<'a>>;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mxid_str = env::args().nth(1).unwrap();

    let vault = Matrix::new(MatrixUserCreds {
        mxid: mxid_str.as_str().into(),
        token: env::args().nth(2).unwrap(),
    });

    let mut wallet = Wallet::new(vault);

    wallet
        .unlock(MatrixCredentials::Keyfile(env::args().nth(3).unwrap()))
        .await?;

    let account = wallet.default_account();
    println!("Default account: {}", account);

    Ok(())
}
