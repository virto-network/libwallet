use libwallet::{self, Language, OSVault};

use std::error::Error;

type Wallet = libwallet::Wallet<OSVault>;

const TEST_USER: &str = "test_user";

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let user = std::env::args()
        .nth(1)
        .unwrap_or_else(|| TEST_USER.to_string());

    let vault = OSVault::new(&user, Language::default());
    let mut wallet = Wallet::new(vault);
    wallet.unlock(()).await?;

    let account = wallet.default_account();
    println!("Default account: {}", account);

    Ok(())
}
