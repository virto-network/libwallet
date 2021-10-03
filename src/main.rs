extern crate clap;
use clap::{App, Arg};
use libwallet::{
     sr25519::{Pair, Public},
     Pair as _, SimpleVault, Wallet,
};
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};

#[async_std::main]
async fn main() {
     let matches = App::new("Wallet Generator")
          .version("0.1.0")
          .author("Daniel Olano <me@olanod.com>")
          .about("Generates Wallet Account")
          .arg(Arg::with_name("seed")
               .short("s")
               .long("from-seed")
               .value_name("SEED or MNEMONIC")
               .help("Generates a wallet address from seed."))
          .arg(Arg::with_name("network")
               .short("n")
               .long("network")
               .value_name("NETWORK")
               .help("Formats the address to specified network."))
          .get_matches();

     let pub_address = get_pub_address(matches.value_of("seed")).await;
     let network: &str = matches.value_of("network").unwrap_or("");

     let address: String = pub_address.to_ss58check_with_version(get_network_format(network));
     println!("Public key (SS58): {}", address);
}

async fn get_pub_address(seed: Option<&str>) -> Public {
     match seed {
          Some(mnemonic) => {
               let vault = SimpleVault::<Pair>::from(mnemonic);
               let mut wallet = Wallet::from(vault);
               wallet.unlock("").await.unwrap();
               let public_add = wallet.root_account().unwrap().public();
               println!("Secret Key: \"{}\"", mnemonic);
               public_add
          }
          None => {
               let vault = SimpleVault::<Pair>::new();
               let mut wallet = Wallet::from(vault);
               wallet.unlock("").await.unwrap();
               let public_add = wallet.root_account().unwrap().public();
               public_add
          }
     }
}

fn get_network_format(network: &str) -> Ss58AddressFormat {
     match network {
          "polkadot" => Ss58AddressFormat::PolkadotAccount,
          "kusama" => Ss58AddressFormat::KusamaAccount,
          _ => Ss58AddressFormat::SubstrateAccount,
     }
}
