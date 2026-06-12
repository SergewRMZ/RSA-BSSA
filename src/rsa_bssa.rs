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
  rng: &mut Rng, 
  public_key: &PK) {
  
  let n = public_key.n();
  
  println!("Módulo n: {}", n);
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::rng;
  use rsa::{RsaPrivateKey, RsaPublicKey};

  #[test]
  fn test_prepare() {
    let mut thread_rng = rng();
    let message = b"Hola Mundo";
    let prepared = prepare(message, &mut thread_rng);
    let hex_string: String = prepared.iter().map(|b| format!("{:02x}", b)).collect();
    println!("{}", hex_string);
  }

  #[test]
  fn test_blind() {
    let mut thread_rng = rng();
    let p = BoxedUint::from_be_hex("e1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc75673488930559c120fd0410194fb8a0da55bd0b81227e843fdca6692ae80e5a5d414116d4803fca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d731684150b63c9a3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba6d6daf108602be26d7071803c67105a5426838e6889d77e8474b29244cefaf418e381b312048b457d73419213063c60ee7b0d81820165864fef93523c9635c22210956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627c42e84a9d3f2774017e32ebca06308a12ecc290c7cd1156dcccfb2311", 2048).unwrap();

    let q = BoxedUint::from_be_hex("c601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c806426b60718c05245650821d39445d3ab591ed10a7339f15d83fe13f6a3dfb20b9452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7d367e9b0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa19ecf962daa7916e21afad09eb62fe9f1cf91b77dc879b7974b490d3ebd2e95426057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd347e59f3f32ad9ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae133846304a2936ad7bc7c9803879d2fc4a28e69291d73dbd799f8bc238385", 2048).unwrap();

    let e = BoxedUint::from(65537u32);

    let encoded_message = "2be01c5669eb676cb3f0002eb636427d61568f3f0579da5b998279a7eb3ab784e5617319376d04809d83e72bef9f0738e7324af3fd1b4f0a35f4f58058ab329495406bdb5ff31a0274be2d137c735ab0d5a591b3129a6cc46fcecc4b41dbc684c965cb30e3eb4864ef18cc8d95b4d6a2002607c821d4d8a7e026ae7bb1f6b4c7c93d1b58e9cd87864d6094b0d8f7e2b5f966473703634fb58c774dd4a24376e0eb262a24b58e3a0b4da4f36ef75651627561ff2ecee9dcbfe1d728cc31a7b46030f7a2815ae9edf9a2a5c0c6d8dbab1b33b9c3bbda5c083670a3550f7d74c4263aad09f8ed1d435fc6295ca4d51fc02c7de9ae28ffd53372c3fa864521b27560daa11ab9daad8d0d747661718d2f79c59d0661b09c74863fa32bdcb1c408d3bd24569c57aecae6e06c0c9deb7303c5b7b1240960fd2413d61b2e3829af8c09874fdba0fe84ca6aa7e7d533f9b0ddfe508f562b132ca2d325f1e73f91a8a6b831a2fd9bc0bd5bfa5ea3a1dee16bd9b264174b9553a4c0c0d62373353355c05b35824e4bae702f49e5a6bf83eaff65af499045bcef1470a0e58ddb21856034af0db96f8636d4a6f1591f34c7224e0c0293e3d3be2139f2797c5ed8b65473ac2f83c52b87f8cf8754ac2f55f5e41e105df1d079a647fb1aa591526295667f37db1129752d024eb03bfe506a43665072118423351ef9b8663376f9fc073141e1e7bc";

    let sk: RsaPrivateKey = RsaPrivateKey::from_p_q(p, q, e).expect("Failed to generate private key");
    let pk: RsaPublicKey = RsaPublicKey::from(&sk);
    
    blind(&mut thread_rng, &pk);
  }
}

