use sha3::{Digest, Sha3_384};

pub fn mgf1(mask_seed: &[u8], mask_len: usize) -> Vec<u8>{
  let mut counter:u32 = 0;
  let mut output: Vec<u8> = Vec::with_capacity(mask_len);

  while output.len() < mask_len {
    let mut hasher = Sha3_384::new();
    hasher.update(mask_seed);
    hasher.update(counter.to_be_bytes());
    let digest = hasher.finalize();
    let bytes_to_copy = digest.len().min(mask_len - output.len()); 
    output.extend_from_slice(&digest[..bytes_to_copy]);
    counter = counter.wrapping_add(1);
  }
  output  
}

pub fn calculate_digest<D: Digest> (parts: &[&[u8]], output: &mut [u8]) {
  let mut hasher = D::new();
  for part in parts {
    hasher.update(part);
  }
  output.copy_from_slice(hasher.finalize().as_slice());
}