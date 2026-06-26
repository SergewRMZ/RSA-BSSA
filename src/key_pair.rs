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
use rsa::{RsaPublicKey, RsaPrivateKey};
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
        let p = BoxedUint::from_be_hex("e1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc75673488930559c120fd0410194fb8a0da55bd0b81227e843fdca6692ae80e5a5d414116d4803fca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d731684150b63c9a3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba6d6daf108602be26d7071803c67105a5426838e6889d77e8474b29244cefaf418e381b312048b457d73419213063c60ee7b0d81820165864fef93523c9635c22210956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627c42e84a9d3f2774017e32ebca06308a12ecc290c7cd1156dcccfb2311", 2048).unwrap();
        let q = BoxedUint::from_be_hex("c601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c806426b60718c05245650821d39445d3ab591ed10a7339f15d83fe13f6a3dfb20b9452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7d367e9b0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa19ecf962daa7916e21afad09eb62fe9f1cf91b77dc879b7974b490d3ebd2e95426057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd347e59f3f32ad9ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae133846304a2936ad7bc7c9803879d2fc4a28e69291d73dbd799f8bc238385", 2048).unwrap();
        let e = BoxedUint::from(65537u32);

        let sk: RsaPrivateKey = RsaPrivateKey::from_p_q(p, q, e).expect("Failed to generate private key");
        let pk: RsaPublicKey = RsaPublicKey::from(&sk);  

        let prepared_msg = hex_to_bytes("8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d").unwrap();

        let bssa_pk: RsaBssaPublicKey<Sha3_384, DeterministicMsg> = RsaBssaPublicKey::new(pk);
        let result = bssa_pk.blind(&mut thread_rng, &prepared_msg);

        if let Ok(blinded_result) = result {
            let blinded_msg_hex: String = blinded_result.blinded_msg.0.iter().map(|x|  format!("{:02x}", x)).collect();

            println!("Mensaje cegado: {}", blinded_msg_hex);
        } 
    }
}   
