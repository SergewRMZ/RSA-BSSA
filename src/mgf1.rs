use sha2::{Digest};
use sha2::digest::Output;
pub fn mgf1<D: Digest>(mask_seed: &[u8], mask_len: usize, ) -> Vec<u8>{
    let mut counter:u32 = 0;
    let mut output: Vec<u8> = Vec::with_capacity(mask_len);

    while output.len() < mask_len {
        let mut hasher = D::new();
        hasher.update(mask_seed);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        let bytes_to_copy = digest.len().min(mask_len - output.len()); 
        output.extend_from_slice(&digest[..bytes_to_copy]);
        counter = counter.wrapping_add(1);
    }
    output  
}

pub fn calculate_digest<D: Digest> (parts: &[&[u8]]) -> Output<D> {
    let mut hasher = D::new();
    for part in parts {
      hasher.update(part);
    }
    hasher.finalize()
}

// pub fn calculate_digest<D: Digest> (parts: &[&[u8]], output: &mut [u8]) {
//   let mut hasher = D::new();
//   for part in parts {
//     hasher.update(part);
//   }
//   output.copy_from_slice(hasher.finalize().as_slice());
// }

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha384;
    #[test]
    fn test_mgf1() {
        let mask_seed = b"Hola Mundo";
        let mask_len = 335;
        let mask = mgf1::<Sha384>(mask_seed, mask_len);
        assert_eq!(mask.len(), mask_len);
    }

    #[test]
    fn test_mgf1_deterministic() {
        let mask_seed = b"Hola Mundo";
        let mask_len = 335;
        let mask1 = mgf1::<Sha384>(mask_seed, mask_len);
        let mask2 = mgf1::<Sha384>(mask_seed, mask_len);
        assert_eq!(mask1, mask2);
    }
}