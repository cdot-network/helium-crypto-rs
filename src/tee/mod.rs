use crate::{
    ecc_compact::{self, Signature},
    keypair, public_key, Error, KeyTag, KeyType as CrateKeyType, Network, Result,
};

pub struct Keypair {
    pub public_key: public_key::PublicKey,
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let sign_result = iotpi_helium_optee::sign(msg);
        match result {
            Ok(bytes) => {
                let signature = ecdsa::Signature::try_from(&bytes[..])?;
                Ok(Signature(signature))
            }
            _ => Err(signature::Error::from_source(err)),
        }
    }
}
