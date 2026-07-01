use std::marker::PhantomData;

use crypto_bigint::Gcd;
use rand::CryptoRng;
use rsa::{BoxedUint, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use sha2::Digest;

use crate::emsa_pss::EMSAPSS;
use crate::rsa_bssa::{BlindResult, BlindedMessage, InverseBlindFactor, MessagePrepare, Randomizer, blind};

#[derive(Debug)]
pub enum RsaBssaError {
    InternalError, 
    UnsupportedParameters,
    EncodingError
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaBssaPublicKey<H: Digest, M: MessagePrepare> {
    inner: RsaPublicKey,
    _phantom: PhantomData<(H, M)>
}

impl <H: Digest, M: MessagePrepare> RsaBssaPublicKey<H, M> {
    pub fn new (inner: RsaPublicKey) -> Self {
        Self {
          inner,
          _phantom: PhantomData
        }
    }

    pub fn blind<R: CryptoRng + ?Sized> (&self, rng: &mut R, msg: &[u8]) -> Result<BlindResult, RsaBssaError> {
        let modulus_bits = self.inner.n_bits_precision() as usize;
        let preffix: Option<Randomizer> = M::prepare(rng);        
        let mut salt = [0u8; 48];
        rng.fill_bytes(&mut salt);

        let emsa = EMSAPSS::new(modulus_bits);
        let encoded: Vec<u8> =  match preffix {
            Some(randomizer) => {
                let mut randomized_msg = Vec::with_capacity(msg.len() + 32);
                randomized_msg.extend_from_slice(randomizer.as_ref());
                randomized_msg.extend_from_slice(msg);
                emsa.encode::<H>(&randomized_msg, &salt)?
            }

            None => {
                emsa.encode::<H>(msg, &salt)?
            }
        };

        let n = self.inner.n();
        let n_bits = n.bits_precision();
        let em_buint = BoxedUint::from_be_slice(&encoded, n_bits).map_err(|_| RsaBssaError::InternalError)?;
        
        if em_buint.gcd(n) != BoxedUint::one() {
            return  Err(RsaBssaError::UnsupportedParameters);
        }

        let (blinded_msg, secret) = blind(em_buint, rng, &self.inner);
        
        Ok(BlindResult {
            blinded_msg: BlindedMessage(blinded_msg.to_be_bytes().into_vec()),
            secret: InverseBlindFactor(secret.to_be_bytes().into_vec()),
            rnd_msg: preffix
        })
    }
}

#[cfg(test)]
mod tests {
use rsa::RsaPublicKey;
use crypto_bigint::BoxedUint;
use rand::rng;
use sha3::Sha3_384;
use crate::rsa_bssa::DeterministicMsg;
use crate::key_pair::RsaBssaPublicKey;

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
}

#[test]
    fn test_blind_message() {
        let mut thread_rng = rng();
        let e = BoxedUint::from(65537u32);
        let n = BoxedUint::from_be_hex("aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5", 4096).unwrap();
        
        let pk: RsaPublicKey = RsaPublicKey::new(n, e).expect("Error creating public key");
        let prepared_msg = hex_to_bytes("8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d").unwrap();

        let bssa_pk: RsaBssaPublicKey<Sha3_384, DeterministicMsg> = RsaBssaPublicKey::new(pk);
        let result = bssa_pk.blind(&mut thread_rng, &prepared_msg);
        if let Ok(blinded_result) = result {
            let blinded_msg_hex: String = blinded_result.blinded_msg.0.iter().map(|x|  format!("{:02x}", x)).collect();
            let unblinder_factor: String = blinded_result.secret.0.iter().map(|x| format!("{:02x}", x)).collect();
            println!("Unblinder factor: {}", unblinder_factor);
            println!("Mensaje cegado: {}", blinded_msg_hex);

        } 
    }
}   
