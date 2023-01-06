use aes::cipher::{generic_array::GenericArray, NewCipher, StreamCipher};
use aes::Aes256Ctr;

use core::convert::{TryFrom, TryInto};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;
use surf::{get, Client, Config, Url};

#[derive(Debug)]
pub enum MatrixCredentials {
    Passphrase(String),
    Keyfile(String),
}

impl From<String> for MatrixCredentials {
    fn from(s: String) -> Self {
        if s.split_whitespace().count() > 1 {
            MatrixCredentials::Keyfile(s.into())
        } else {
            MatrixCredentials::Passphrase(s.into())
        }
    }
}

pub struct MxId<'a> {
    id: &'a str,
}

impl<'a> From<&'a str> for MxId<'a> {
    fn from(id: &'a str) -> Self {
        MxId { id }
    }
}

impl<'a> MxId<'a> {
    pub fn username(&self) -> &'a str {
        self.id
    }

    pub fn server(&self) -> &'a str {
        let index = self.id.find(':').expect("invalid matrix id");
        &self.id[index + 1..]
    }
}

pub struct MatrixStorage<'a> {
    username: &'a str,
    token: String,
    client: Client,
}
#[derive(Deserialize, Debug)]
pub struct BaseUrl {
    base_url: String,
}

#[derive(Deserialize, Debug)]
pub struct WellKnownMatrixServer {
    #[serde(alias = "m.homeserver")]
    home_server: BaseUrl,
}

#[derive(Deserialize)]
struct KeyID {
    key: String,
}

impl<'mxid> MatrixStorage<'mxid> {
    pub async fn new(mx_id: &MxId<'mxid>, token: &str) -> Result<MatrixStorage<'mxid>> {
        let res: WellKnownMatrixServer = get(format!(
            "https://{}/.well-known/matrix/client",
            mx_id.server()
        ))
        .recv_json()
        .await
        .map_err(|_| MatrixError::UnresolvedMatrixServer)?;

        Ok(MatrixStorage {
            username: mx_id.username(),
            token: token.to_string(),
            client: Config::new()
                .set_base_url(Url::parse(&res.home_server.base_url).expect("valid URL"))
                .try_into()
                .expect("build client successfully"),
        })
    }

    pub async fn get_secret_from_storage(
        &self,
        secret_name: &str,
        credentials: &MatrixCredentials,
    ) -> Result<Option<Vec<u8>>> {
        match credentials {
            MatrixCredentials::Keyfile(storage_key) => self
                .get_secret_using_keyfile(secret_name, storage_key)
                .await
                .map(Some)
                .or_else(|err| match err {
                    MatrixError::NotFound => Ok(None),
                    _ => Err(err),
                }),
            MatrixCredentials::Passphrase(storage_key) => self
                .get_secret_using_passphrase(secret_name, storage_key)
                .await
                .map(Some)
                .or_else(|err| match err {
                    MatrixError::NotFound => Ok(None),
                    _ => Err(err),
                }),
        }
    }

    pub async fn save_secret_in_storage(
        &self,
        secret_name: &str,
        secret: &[u8],
        credentials: &MatrixCredentials,
    ) -> Result<()> {
        match credentials {
            MatrixCredentials::Keyfile(storage_key) => {
                self.save_secret_using_keyfile(secret_name, secret, storage_key)
                    .await
            }
            MatrixCredentials::Passphrase(storage_key) => {
                self.save_secret_using_passphrase(secret_name, secret, storage_key)
                    .await
            }
        }
    }

    async fn get_secret_using_keyfile(
        &self,
        secret_name: &str,
        storage_key: &str,
    ) -> Result<Vec<u8>> {
        let key_data = self.get_storage_key_data().await?;
        let decoded_key = MatrixStorageKey::from_recovery_key(storage_key, key_data)?;
        decoded_key.validate_key()?;
        let secret = self.get_secret(secret_name).await?;
        let secret = decoded_key.decrypt(&secret)?;

        Ok(secret)
    }

    async fn get_secret_using_passphrase(
        &self,
        secret_name: &str,
        passphrase: &str,
    ) -> Result<Vec<u8>> {
        let key_data = self.get_storage_key_data().await?;
        let storage_key = MatrixStorageKey::from_passphrase(passphrase, key_data)?;
        let secret = self.get_secret(secret_name).await?;
        let secret = storage_key.decrypt(&secret)?;

        Ok(secret)
    }

    async fn get_secret(&self, secret_name: &str) -> Result<MatrixStorageSecret> {
        let request_url = format!(
            "/_matrix/client/v3/user/{username}/account_data/{secret_name}",
            username = self.username,
            secret_name = secret_name,
        );

        self.make_get_request::<MatrixStorageSecret>(&request_url)
            .await
    }

    // Get data to validate storage key
    async fn get_storage_key_data(&self) -> Result<KeyData> {
        // get https://{server}/_matrix/client/r0/user/{username}/account_data/m.secret_storage.default_key
        let request_url = format!(
            "/_matrix/client/r0/user/{username}/account_data/m.secret_storage.default_key",
            username = self.username
        );

        let key_id = self.make_get_request::<KeyID>(&request_url).await?;

        // get https://{server}/_matrix/client/r0/user/{username}/account_data/m.secret_storage.key.{id_from_previous_request}
        let request_url = format!(
            "/_matrix/client/r0/user/{username}/account_data/m.secret_storage.key.{id_from_previous_request}",
            username = self.username, id_from_previous_request= key_id.key
        );

        self.make_get_request::<KeyData>(&request_url).await
    }

    async fn make_get_request<'a, T>(&self, url: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut res = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", &self.token))
            .await
            .map_err(|_| MatrixError::ConnectionFailed)?;

        if res.status() == 404 {
            return Err(MatrixError::NotFound);
        }

        let res: T = res
            .body_json()
            .await
            .map_err(|_| MatrixError::MappingError)?;

        Ok(res)
    }

    async fn save_secret_using_keyfile(
        &self,
        secret_name: &str,
        secret: &[u8],
        storage_key: &str,
    ) -> Result<()> {
        let key_data = self.get_storage_key_data().await?;
        let storage_key = MatrixStorageKey::from_recovery_key(storage_key, key_data)?;

        storage_key.validate_key()?;

        let encrypted = storage_key.encrypt(secret)?;
        let secret = MatrixStorageSecret { encrypted };

        self.save_secret(secret_name, &secret).await
    }

    async fn save_secret_using_passphrase(
        &self,
        secret_name: &str,
        secret: &[u8],
        passphrase: &str,
    ) -> Result<()> {
        let key_data = self.get_storage_key_data().await?;

        let key = MatrixStorageKey::from_passphrase(passphrase, key_data)?;
        key.validate_key()?;

        let encrypted = key.encrypt(secret)?;

        let secret = MatrixStorageSecret { encrypted };

        self.save_secret(secret_name, &secret).await
    }

    async fn save_secret(&self, secret_name: &str, secret: &MatrixStorageSecret) -> Result<()> {
        let request_url = format!(
            "/_matrix/client/v3/user/{username}/account_data/{secret_name}",
            username = self.username,
            secret_name = secret_name,
        );

        self.client
            .put(request_url)
            .header("Authorization", format!("Bearer {}", &self.token))
            .body_json(&secret)
            .unwrap()
            .await
            .map_err(|_| MatrixError::ConnectionFailed)?;

        Ok(())
    }
}

impl MatrixStorageKey {
    fn create_iv() -> [u8; 16] {
        crate::util::random_bytes(&mut rand_core::OsRng)
    }

    pub fn from_passphrase(passphrase: &str, key_data: KeyData) -> Result<MatrixStorageKey> {
        let key = match key_data.algorithm.as_str() {
            "m.pbkdf2" => {
                let passphrase_info = key_data
                    .passphrase_info
                    .as_ref()
                    .ok_or(MatrixError::PassphraseInfoMissing)?;

                Ok(Self::derive_from_passphrase(
                    passphrase,
                    &passphrase_info.salt,
                    passphrase_info.iterations,
                ))
            }
            "m.secret_storage.v1.aes-hmac-sha2" => {
                let passphrase_info = key_data
                    .passphrase
                    .as_ref()
                    .ok_or(MatrixError::PassphraseInfoMissing)?;

                Ok(Self::derive_from_passphrase(
                    passphrase,
                    &passphrase_info.salt,
                    passphrase_info.iterations,
                ))
            }
            _ => Err(MatrixError::PassphraseError),
        }?;

        Ok(Self {
            key,
            key_data: Some(key_data),
        })
    }

    /// Retrieve key from passphrase.
    fn derive_from_passphrase(passphrase: &str, salt: &str, rounds: u32) -> [u8; 32] {
        let mut key = [0u8; 32];

        pbkdf2::<Hmac<Sha512>>(passphrase.as_bytes(), salt.as_bytes(), rounds, &mut key);

        key
    }

    pub fn from_recovery_key(recovery_key: &str, key_data: KeyData) -> Result<MatrixStorageKey> {
        // base58 decode
        let key = Self::derive_from_keyfile(recovery_key)?;

        Ok(MatrixStorageKey {
            key,
            key_data: Some(key_data),
        })
    }

    pub fn derive_from_keyfile(recovery_key: &str) -> Result<[u8; 32]> {
        // base58 decode
        let mut key = [0u8; 35];

        let decoded_size = bs58::decode(recovery_key.split_whitespace().collect::<String>())
            .into(&mut key)
            .map_err(|_| MatrixError::InvalidStorageKey)?;

        let mut parity: u8 = 0;

        for i in key {
            parity ^= i;
        }

        if parity != 0 {
            return Err(MatrixError::InvalidStorageKey);
        }
        // check if we have the correct header prefix
        // OLM_RECOVERY_KEY_PREFIX = [0x8B, 0x01];
        let prefix = [0x8B, 0x01];

        if key[0] != prefix[0] || key[1] != prefix[1] {
            return Err(MatrixError::InvalidStorageKey);
        }

        // verify that the length of the key is correct
        if decoded_size - 3 != 32 {
            return Err(MatrixError::InvalidStorageKey);
        }

        // strip the prefix and the parity byte to return the raw key
        let slice = &key[2..34];

        Ok(<[u8; 32]>::try_from(slice).unwrap())
    }

    pub fn validate_key(&self) -> Result<()> {
        let keys = self.derive_keys()?;
        let key_data = self.key_data.as_ref().ok_or(MatrixError::StorageKeyError)?;

        let encrypted =
            Self::encrypt_bytes(&[0u8; 32], &keys, &base64::decode(&key_data.iv).unwrap())?;

        if key_data.mac == encrypted.mac {
            return Ok(());
        }

        Err(MatrixError::InvalidStorageKey)
    }

    pub fn derive_keys(&self) -> Result<Keys> {
        // derive keys
        //aes key
        let zerosalt: [u8; 32] = [0; 32];
        let mut prk = HmacSha256::new_from_slice(&zerosalt).unwrap();
        prk.update(&self.key);
        let key = prk.finalize().into_bytes();
        let mut result = HmacSha256::new_from_slice(&key).unwrap();
        let b: [u8; 1] = [1];
        result.update(&b);
        let aes_key = result.finalize().into_bytes();

        //hmac key
        let b: [u8; 1] = [2];
        let mut result = HmacSha256::new_from_slice(&key).unwrap();
        result.update(&aes_key);
        result.update(&b);
        let hmac_key = result.finalize().into_bytes();

        Ok(Keys {
            hmac: hmac_key.into(),
            aes: aes_key.into(),
        })
    }

    pub fn encrypt(&self, bytes: &[u8]) -> Result<Encrypted> {
        // encrypt ciphertext with aes-key, iv from key_data and name=""

        let keys = self.derive_keys()?;
        let iv = Self::create_iv();

        Self::encrypt_bytes(bytes, &keys, &iv)
    }

    pub fn encrypt_bytes(bytes: &[u8], keys: &Keys, nonce: &[u8]) -> Result<Encrypted> {
        // encrypt ciphertext with aes-key, iv from key_data and name=""

        let nonce = GenericArray::from_slice(nonce);
        let key = GenericArray::from_slice(&keys.aes);

        let mut cipher = Aes256Ctr::new(key, nonce);

        let mut data = bytes.to_owned();
        cipher.apply_keystream(&mut data);

        // compare mac from encrypt and key_data
        let mut mac =
            HmacSha256::new_from_slice(&keys.hmac).map_err(|_| MatrixError::StorageKeyError)?;

        mac.update(&data);

        let result = mac.finalize();
        let mac = result.into_bytes();

        Ok(Encrypted {
            iv: base64::encode(nonce),
            ciphertext: base64::encode(data),
            mac: base64::encode(mac),
        })
    }

    fn decrypt(&self, secret: &MatrixStorageSecret) -> Result<Vec<u8>> {
        // derive our keys
        let keys = self.derive_keys()?;

        // decode our ciphertext, as it is base64 encoded
        let cipher = base64::decode(&secret.encrypted.ciphertext)
            .map_err(|_| MatrixError::EncryptionError)?;
        // HMAC our cipher with the generated HMAC key, base64'ing it afterwards
        let mut mac =
            HmacSha256::new_from_slice(&keys.hmac).map_err(|_| MatrixError::EncryptionError)?;
        mac.update(&cipher);
        let hmac = base64::encode(mac.finalize().into_bytes());
        // if macs dont match, error
        if hmac != secret.encrypted.mac {
            return Err(MatrixError::EncryptionError);
        }

        let nonce = base64::decode(secret.encrypted.iv.clone()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(&keys.aes);

        let mut decipher = Aes256Ctr::new(key, nonce);
        let mut data = base64::decode(&secret.encrypted.ciphertext)
            .map_err(|_| MatrixError::EncryptionError)?;

        decipher.apply_keystream(&mut data);

        Ok(data)
    }
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize, Debug)]
struct MatrixStorageSecret {
    encrypted: Encrypted,
}

#[derive(Deserialize, Serialize, Debug)]
struct Encrypted {
    iv: String,
    ciphertext: String,
    mac: String,
}
#[derive(Debug)]
struct MatrixStorageKey {
    key: [u8; 32],
    key_data: Option<KeyData>,
}

#[derive(Deserialize, Debug)]
struct KeyData {
    algorithm: String,
    iv: String,
    mac: String,
    passphrase_info: Option<PassphraseInfo>,
    passphrase: Option<PassphraseInfo>,
}

#[derive(Deserialize, Debug)]
struct PassphraseInfo {
    iterations: u32,
    salt: String,
}

#[derive(Debug)]
struct Keys {
    hmac: [u8; 32], //String,
    aes: [u8; 32],  //String,
}

pub type Result<T> = core::result::Result<T, MatrixError>;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum MatrixError {
    #[cfg_attr(feature = "std", error("Connection to server failed"))]
    ConnectionFailed,
    #[cfg_attr(feature = "std", error("Cannot retrieve passphrase info"))]
    PassphraseInfoMissing,
    #[cfg_attr(feature = "std", error("Error with passphrase"))]
    PassphraseError,
    #[cfg_attr(feature = "std", error("Error with storage key"))]
    StorageKeyError,
    #[cfg_attr(feature = "std", error("Invalid storage key"))]
    InvalidStorageKey,
    #[cfg_attr(feature = "std", error("Error with encryp/decrypt"))]
    EncryptionError,
    #[cfg_attr(feature = "std", error("Error with remote objects mapping"))]
    MappingError,
    #[cfg_attr(feature = "std", error("Request not found"))]
    NotFound,
    #[cfg_attr(
        feature = "std",
        error("Unable to resolve matrix server via .well-known/matrix/server")
    )]
    UnresolvedMatrixServer,
}

#[cfg(test)]
mod tests {
    // for MatrixKeyOps
    use crate::vault::matrix::storage::MatrixStorageKey;

    const KEY: [u8; 32] = [
        177, 233, 182, 25, 203, 212, 180, 46, 125, 20, 100, 5, 52, 173, 164, 18, 7, 123, 103, 28,
        125, 0, 90, 80, 171, 42, 204, 85, 83, 143, 72, 204,
    ];
    const AES_KEY: [u8; 32] = [
        36, 210, 94, 26, 31, 61, 150, 36, 254, 74, 165, 26, 71, 248, 25, 61, 13, 192, 116, 71, 100,
        63, 154, 14, 3, 194, 206, 233, 65, 179, 74, 234,
    ];
    const HMAC_KEY: [u8; 32] = [
        28, 174, 46, 179, 162, 17, 56, 238, 27, 97, 154, 77, 83, 112, 165, 18, 171, 178, 95, 179,
        201, 1, 140, 151, 113, 136, 115, 154, 12, 217, 86, 122,
    ];
    const PASSPHRASE: &str = "akJUeiZ2i4P27Uv";
    const KEYFILE: &str = "EsTu q3iZ vRpP LibY Pq7G NJ2v fQdA eWNf W1ng NRkx NfcF XkLe";
    const SALT: &str = "pHUPIs4yOXLHUadIqDOqO0FYrzNx5CFm";
    const IV: &str = "8QZZ8CEZ40oUUawQ845hQw==";
    const HMAC: &str = "YGNxa56Vy48l1NQjwGKMxpZiy+ExyDgRn8xzqCIzGks=";

    #[test]
    /// Retrieve key from passphrase.
    fn key_from_passphrase_test() {
        let result = MatrixStorageKey::derive_from_passphrase(PASSPHRASE, SALT, 500000);

        assert_eq!(result, KEY);
    }

    #[test]
    fn decode_recovery_key_test() {
        let matrix_key = MatrixStorageKey::derive_from_keyfile(KEYFILE).unwrap();

        assert_eq!(matrix_key, KEY);
    }

    #[test]
    // derive keys test
    fn derive_keys_test() {
        let matrix_key = super::MatrixStorageKey {
            key: KEY,
            key_data: None,
        };

        let keys = MatrixStorageKey::derive_keys(&matrix_key).unwrap();

        assert_eq!(keys.aes, AES_KEY);
        assert_eq!(keys.hmac, HMAC_KEY);
    }

    #[test]
    // encrypt test
    fn encrypt_bytes_test() {
        let keys = super::Keys {
            aes: AES_KEY,
            hmac: HMAC_KEY,
        };

        let encrypted =
            MatrixStorageKey::encrypt_bytes(&[0u8; 32], &keys, &base64::decode(IV).unwrap())
                .expect("Error in test encrypting bytes.");

        assert_eq!(encrypted.mac, HMAC);
    }

    #[test]
    // decrypt test
    fn decrypt_secret_test() {
        let secret = super::MatrixStorageSecret {
            encrypted: super::Encrypted {
                iv: IV.to_string(),
                ciphertext: "+rov/SarxArWx3KB2B1xIe9zOIzrLkEwi6cawkr7CIA=".to_string(),
                mac: "YGNxa56Vy48l1NQjwGKMxpZiy+ExyDgRn8xzqCIzGks=".to_string(),
            },
        };

        let matrix_key = super::MatrixStorageKey {
            key: KEY,
            key_data: None,
        };

        let decrypted = matrix_key
            .decrypt(&secret)
            .expect("Error decrypting secret test");

        assert_eq!(decrypted, [0u8; 32].to_vec());
    }
}
