use sha2::Digest;
use sha2::digest::OutputSizeUser;
use crate::mgf1::mgf1;
use crate::mgf1::calculate_digest;
#[derive(Debug)]
pub enum EMSAPSSError {
  EncodingError
}
pub struct EMSAPSS {
  em_bits: usize
}

impl EMSAPSS {
  pub fn new (em_bits: usize) -> Self {
    Self {
      em_bits,
    }
  }

  pub fn encode<D: Digest>(&self, message: &[u8], salt: &[u8]) -> Result<Vec<u8>, EMSAPSSError>{
    let em_len = self.em_bits.div_ceil(8);
    let h_len: usize = <D as OutputSizeUser>::output_size();
    let s_len = salt.len();

    if em_len < h_len + s_len + 2 {
      return Err(EMSAPSSError::EncodingError);
    }
    let mut em: Vec<u8> = vec![0u8; em_len];

    let mut m_hash: Vec<u8> = vec![0u8; h_len];
    calculate_digest::<D>(&[message], &mut m_hash);

    let (db, m_prime_hash) = em.split_at_mut(em_len - h_len - 1);
    let m_prime_hash = &mut m_prime_hash[..h_len];

    calculate_digest::<D>
      (&[&[0u8; 8], &m_hash, &salt],
      m_prime_hash
    );

    let db_len = db.len();
    db[db_len - s_len - 1] = 0x01;
    db[(db_len - s_len)..].copy_from_slice(salt);

    let mask: Vec<u8> = mgf1::<D>(m_prime_hash, db.len());
    for (db_byte, mask_byte) in db.iter_mut().zip(mask.iter()) {
      *db_byte ^= mask_byte;
    }
    // db[0] &= 0xff >> (8 * em_len - (self.em_bits - 1));
    db[0] &= 0x7f;
    em[em_len - 1] = 0xbc;
    Ok(em)
  } 
}

#[cfg(test)]
mod tests {
  use core::panic;
  use sha2::Sha384;
  use super::*;
  fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect()
  }

  #[test]
  fn test_emsa_pss() {
    let em = EMSAPSS::new(40);
    let prepared_hex = "8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d";
    let salt_hex = "051722b35f458781397c3a671a7d3bd3096503940e4c4f1aaa269d60300ce449555cd7340100df9d46944c5356825abf";
    let em_expected = "2be01c5669eb676cb3f0002eb636427d61568f3f0579da5b998279a7eb3ab784e5617319376d04809d83e72bef9f0738e7324af3fd1b4f0a35f4f58058ab329495406bdb5ff31a0274be2d137c735ab0d5a591b3129a6cc46fcecc4b41dbc684c965cb30e3eb4864ef18cc8d95b4d6a2002607c821d4d8a7e026ae7bb1f6b4c7c93d1b58e9cd87864d6094b0d8f7e2b5f966473703634fb58c774dd4a24376e0eb262a24b58e3a0b4da4f36ef75651627561ff2ecee9dcbfe1d728cc31a7b46030f7a2815ae9edf9a2a5c0c6d8dbab1b33b9c3bbda5c083670a3550f7d74c4263aad09f8ed1d435fc6295ca4d51fc02c7de9ae28ffd53372c3fa864521b27560daa11ab9daad8d0d747661718d2f79c59d0661b09c74863fa32bdcb1c408d3bd24569c57aecae6e06c0c9deb7303c5b7b1240960fd2413d61b2e3829af8c09874fdba0fe84ca6aa7e7d533f9b0ddfe508f562b132ca2d325f1e73f91a8a6b831a2fd9bc0bd5bfa5ea3a1dee16bd9b264174b9553a4c0c0d62373353355c05b35824e4bae702f49e5a6bf83eaff65af499045bcef1470a0e58ddb21856034af0db96f8636d4a6f1591f34c7224e0c0293e3d3be2139f2797c5ed8b65473ac2f83c52b87f8cf8754ac2f55f5e41e105df1d079a647fb1aa591526295667f37db1129752d024eb03bfe506a43665072118423351ef9b8663376f9fc073141e1e7bc";

    let message_bytes = hex_to_bytes(prepared_hex).unwrap();
    let salt_bytes = hex_to_bytes(salt_hex).unwrap();

    let em = em.encode::<Sha384>(&message_bytes, &salt_bytes);
    match em {
      Ok(em) => {
        let em_hex: String = em.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(em.len(), 512, "La longitud de salida no coincide");
        assert_eq!(em_hex, em_expected);
      }

      Err(e) => {
        panic!("Error: {:?}", e);
      }
    }
    
  }
}

