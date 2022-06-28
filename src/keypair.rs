use crate::*;
use std::ops::Deref;

/// Defines a trait for signing messages. Rather than the signature::Signer
/// trait which deals with exact signature sizes, this trait allows for variable
/// sized signatures, since the ECDSA signature is DER encoded.
pub trait Sign {
    /// Sign the given message
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

#[derive(PartialEq, Debug)]
pub enum Keypair {
    Ed25519(ed25519::Keypair),
    EccCompact(ecc_compact::Keypair),
    #[cfg(feature = "ecc608")]
    Ecc608(ecc608::Keypair),
    #[cfg(feature = "tpm")]
    TPM(tpm::Keypair),
    #[cfg(feature = "tee")]
    Tee(tee::Keypair),
}

pub struct SharedSecret(ecc_compact::SharedSecret);

impl Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(keypair) => keypair.sign(msg),
            Self::EccCompact(keypair) => keypair.sign(msg),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.sign(msg),
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => keypair.sign(msg),
            #[cfg(feature = "tee")]
            Self::Tee(keypair) => keypair.sign(msg),
        }
    }
}

impl Keypair {
    pub fn generate<R>(key_tag: KeyTag, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        match key_tag.key_type {
            KeyType::EccCompact => {
                Self::EccCompact(ecc_compact::Keypair::generate(key_tag.network, csprng))
            }
            KeyType::Ed25519 => Self::Ed25519(ed25519::Keypair::generate(key_tag.network, csprng)),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => panic!("not supported"),
        }
    }

    pub fn generate_from_entropy(key_tag: KeyTag, entropy: &[u8]) -> Result<Keypair> {
        match key_tag.key_type {
            KeyType::EccCompact => Ok(Self::EccCompact(
                ecc_compact::Keypair::generate_from_entropy(key_tag.network, entropy)?,
            )),
            KeyType::Ed25519 => Ok(Self::Ed25519(ed25519::Keypair::generate_from_entropy(
                key_tag.network,
                entropy,
            )?)),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => panic!("not supported"),
        }
    }

    pub fn key_tag(&self) -> KeyTag {
        match self {
            Self::Ed25519(keypair) => keypair.key_tag(),
            Self::EccCompact(keypair) => keypair.key_tag(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.key_tag(),
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => keypair.key_tag(),
            #[cfg(feature = "tee")]
            Self::Tee(keypair) => keypair.key_tag(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Ed25519(keypair) => &keypair.public_key,
            Self::EccCompact(keypair) => &keypair.public_key,
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => &keypair.public_key,
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => &keypair.public_key,
            #[cfg(feature = "tee")]
            Self::Tee(keypair) => &keypair.public_key,
        }
    }

    pub fn ecdh(&self, public_key: &PublicKey) -> Result<SharedSecret> {
        match self {
            Self::EccCompact(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "tee")]
            Self::Tee(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            _ => Err(Error::invalid_curve()),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(keypair) => keypair.to_vec(),
            Self::EccCompact(keypair) => keypair.to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
            #[cfg(feature = "tpm")]
            Self::TPM(_) => panic!("not supported"),
            #[cfg(feature = "tee")]
            Self::Tee(keypair) => panic!("not supported"),
        }
    }

    pub fn secret_to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(keypair) => keypair.secret_to_vec(),
            Self::EccCompact(keypair) => keypair.secret_to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
            #[cfg(feature = "tpm")]
            Self::TPM(_) => panic!("not supported"),
            #[cfg(feature = "tee")]
            Self::Tee(_) => panic!("not supported"),
        }
    }
}

impl From<ed25519::Keypair> for Keypair {
    fn from(keypair: ed25519::Keypair) -> Self {
        Self::Ed25519(keypair)
    }
}

impl From<ecc_compact::Keypair> for Keypair {
    fn from(keypair: ecc_compact::Keypair) -> Self {
        Self::EccCompact(keypair)
    }
}

#[cfg(feature = "ecc608")]
impl From<ecc608::Keypair> for Keypair {
    fn from(keypair: ecc608::Keypair) -> Self {
        Self::Ecc608(keypair)
    }
}

#[cfg(feature = "tpm")]
impl From<tpm::Keypair> for Keypair {
    fn from(keypair: tpm::Keypair) -> Self {
        Self::TPM(keypair)
    }
}

#[cfg(feature = "tee")]
impl From<tee::Keypair> for Keypair {
    fn from(keypair: tee::Keypair) -> Self {
        Self::Tee(keypair)
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        match KeyType::try_from(input[0])? {
            KeyType::Ed25519 => Ok(ed25519::Keypair::try_from(input)?.into()),
            KeyType::EccCompact => Ok(ecc_compact::Keypair::try_from(input)?.into()),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => Err(Error::invalid_keytype(input[0])),
        }
    }
}

impl Deref for SharedSecret {
    type Target = ecc_compact::SharedSecret;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    use std::sync::Once;

    fn bytes_roundtrip(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        let bytes = keypair.to_vec();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
        assert_eq!(keypair.key_tag(), key_tag);
    }

    fn sign_test_tag(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        sign_test_keypair(&keypair);
    }

    fn sign_test_keypair(key_pair: &Keypair) {
        let signature = key_pair.sign(b"hello world").expect("signature");
        assert!(key_pair
            .public_key()
            .verify(b"hello world", &signature)
            .is_ok())
    }

    fn ecdh_test_tag(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        ecdh_test_keypair(&keypair);
    }

    fn ecdh_test_keypair(key_pair: &Keypair) {
        let other = Keypair::generate(key_pair.key_tag(), &mut OsRng);
        let keypair_shared = key_pair
            .ecdh(other.public_key())
            .expect("keypair shared secret");
        let other_shared = other
            .ecdh(key_pair.public_key())
            .expect("other shared secret");
        assert_eq!(keypair_shared.as_bytes(), other_shared.as_bytes());
    }

    #[test]
    fn bytes_roundtrip_ed25519() {
        bytes_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Ed25519,
        });
        bytes_roundtrip(KeyTag {
            network: Network::TestNet,
            key_type: KeyType::Ed25519,
        })
    }

    #[test]
    fn bytes_roundtrip_ecc_compact() {
        bytes_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
        bytes_roundtrip(KeyTag {
            network: Network::TestNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[test]
    fn sign_ed25519() {
        sign_test_tag(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Ed25519,
        });
    }

    #[test]
    fn sign_ecc_compact() {
        sign_test_tag(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn sign_tpm() {
        let keypair = tpm::Keypair::from_key_path(Network::MainNet, "HS/SRK/MinerKey").unwrap();

        sign_test_keypair(&Keypair::TPM(keypair));
    }

    #[test]
    fn ecdh_ecc_compact() {
        ecdh_test_tag(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn ecdh_tpm() {
        let keypair = tpm::Keypair::from_key_path(Network::MainNet, "HS/SRK/MinerKey").unwrap();

        ecdh_test_keypair(&Keypair::TPM(keypair));
    }

    #[cfg(feature = "tee")]
    static INIT: Once = Once::new();

    #[cfg(feature = "tee")]
    fn tee_setup() {
        INIT.call_once(|| {
            iotpi_helium_optee::helium_init();
        });
    }

    #[cfg(feature = "tee")]
    #[test]
    fn ecdh_tee() {
        use p256::{
            self,
            elliptic_curve::{
                bigint::Encoding,
                sec1::{self, FromEncodedPoint, ToCompactEncodedPoint},
                Curve,
            },
            CompressedPoint, EncodedPoint, NistP256, PublicKey,
        };
        use std::convert::{From, TryFrom, TryInto};

        tee_setup();
        let pk = iotpi_helium_optee::ecc_publickey();
        assert!(pk.is_ok());
        let pk = pk.unwrap();

        let mut key_bytes = CompressedPoint::default();
        key_bytes[0] = sec1::Tag::Compact.into();
        key_bytes[1..(<NistP256 as Curve>::UInt::BYTE_SIZE + 1)].copy_from_slice(&pk.0);
        // handcoded generated compact_point similar to 'to_compact_encoded_point'
        // whose execution failed.
        let compact_point = p256::EncodedPoint::from_bytes(&key_bytes)
            .map_err(p256::elliptic_curve::Error::from)
            .expect("cannot encoded point");
        let pubkey = p256::PublicKey::from_encoded_point(&compact_point).unwrap();

        let ecc_pubkey = ecc_compact::PublicKey(pubkey);

        let keypair_pubkey = public_key::PublicKey::for_network(Network::MainNet, ecc_pubkey);
        let keypair = tee::Keypair {
            network: Network::MainNet,
            public_key: keypair_pubkey,
        };
        ecdh_test_keypair(&Keypair::Tee(keypair));
    }
}
