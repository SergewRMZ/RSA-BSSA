use sha3::{Sha3_384};
use crate::mgf1::mgf1;
use crate::mgf1::calculate_digest;

pub struct EMSAPSS {
  em_bits: usize
}

impl EMSAPSS {
  pub fn new (em_bits: usize) -> Self {
    Self {
      em_bits,
    }
  }

  pub fn encode(&self, message: &[u8], salt: &[u8]) -> Vec<u8>{
    let em_len = self.em_bits.div_ceil(8);
    let mut m_hash = [0u8; 48];
    calculate_digest::<Sha3_384>(&[message], &mut m_hash);

    let mut m_prime_hash = [0u8; 48];
    calculate_digest::<Sha3_384>
      (&[&[0u8; 8], &m_hash, &salt],
        &mut m_prime_hash
    );

    let db_len = em_len - m_hash.len() - 1;
    let mut db: Vec<u8> = vec![0u8; db_len];
    let ps_len: usize = db_len - salt.len() - 1;
    db[ps_len] = 0x01;
    db[(ps_len + 1)..].copy_from_slice(salt);

    let mask: Vec<u8> = mgf1(&m_prime_hash, db_len);
    for (db_byte, mask_byte) in db.iter_mut().zip(mask.iter()) {
      *db_byte ^= mask_byte;
    }
    db[0] &= 0xff >> (8 * em_len - self.em_bits);
    let mut em = Vec::with_capacity(em_len);
    em.extend_from_slice(&db);
    em.extend_from_slice(&m_prime_hash);
    em.push(0xbc);
    em
  } 
}

