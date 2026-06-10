use crypto_bigint::{NonZero, RandomMod, BoxedUint};
use rsa::rand_core::CryptoRng;
use rsa::traits::PublicKeyParts;

pub fn prepare<Rng: CryptoRng + ?Sized>(message: &[u8], rng: &mut Rng) -> Vec<u8> {
  const SALT_LEN: usize = 48;
  let mut salt = [0u8; 48];
  rng.fill_bytes(&mut salt);

  let mut prepared = vec![0u8; message.len() + SALT_LEN];
  prepared[..SALT_LEN].copy_from_slice(&salt);
  prepared[SALT_LEN..].copy_from_slice(&message);
  prepared
}


pub fn blind<Rng: CryptoRng + ?Sized, PK: PublicKeyParts>(
  blinded_message: &BoxedUint,
  rng: &mut Rng, 
  public_key: &PK) {
  
  let n = public_key.n();
  
  println!("Módulo n: {}", n);
}

#[cfg(test)]
mod tests {
  use crate::emsa_pss::EMSAPSS;

use super::*;
  use rand::{Rng, rng};
  use rsa::{RsaPrivateKey, RsaPublicKey};

  fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
  }

  #[test]
  fn test_prepare() {
    let mut thread_rng = rng();
    let message = b"Hola Mundo";
    let prepared = prepare(message, &mut thread_rng);
    let hex_string: String = prepared.iter().map(|b| format!("{:02x}", b)).collect();
    println!("{}", hex_string);
  }
}

