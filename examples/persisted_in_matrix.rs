use libwallet::{self, vault::Matrix};
use std::{env, error::Error};

type Wallet<'a> = libwallet::Wallet<Matrix<'a>>;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mxid = args.next().expect("MatrixID");

    let vault = Matrix::new(mxid.as_str(), args.next().expect("Access token"));
    let mut wallet = Wallet::new(vault);

    wallet
        .unlock(args.next().expect("Storage key or passphrase"))
        .await?;

    let account = wallet.default_account();
    println!("Default account: {}", account);

    Ok(())
}
