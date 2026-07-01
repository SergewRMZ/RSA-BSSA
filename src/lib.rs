use rsa::{BoxedUint, RsaPublicKey};
use sha3::Sha3_384;
use wasm_bindgen::prelude::*;

use crate::{key_pair::{RsaBssaError, RsaBssaPublicKey}};
use crate::rsa_bssa::{RandomizedMsg, BlindResult};
mod mgf1;
mod emsa_pss;
mod rsa_bssa;
pub mod key_pair;


#[wasm_bindgen]
pub struct JsBlindResult {
    blinded_msg: Vec<u8>,
    secret: Vec<u8>,
    rnd_msg: Option<[u8; 32]>
}

#[wasm_bindgen]
pub struct JsRsaBssaPublicKey {
    inner: RsaBssaPublicKey<Sha3_384, RandomizedMsg>,
}

impl From<BlindResult> for JsBlindResult {
    fn from(value: BlindResult) -> Self {
        Self { 
            blinded_msg: value.blinded_msg.0, 
            secret: value.secret.0, 
            rnd_msg: value.rnd_msg.map(|r| r.0)
        }
    }
}

#[wasm_bindgen]
impl JsBlindResult {
    #[wasm_bindgen(getter)]
    pub fn blinded_message(&self) -> Vec<u8> {
        self.blinded_msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn rnd_message(&self) -> Option<Vec<u8>> {
        self.rnd_msg.map(|r| r.to_vec())
    }
}

impl From<RsaBssaError> for JsValue {
    fn from(error: RsaBssaError) -> Self {
        match error {
            RsaBssaError::InternalError => JsValue::from_str("RSA_BSSA_INTERNAL_ERROR"),
            RsaBssaError::UnsupportedParameters => JsValue::from_str("UNSUPPORTED_PARAMETERS"),
            RsaBssaError::EncodingError => JsValue::from_str("ENCODING_ERROR")
        }
    }
}

#[wasm_bindgen]
impl JsRsaBssaPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(n_bytes: &[u8], e_bytes: &[u8]) -> Result<JsRsaBssaPublicKey, JsValue>{
        let n = BoxedUint::from_be_slice_vartime(n_bytes);
        let e = BoxedUint::from_be_slice_vartime(e_bytes);
        let pk: RsaPublicKey = RsaPublicKey::new(n, e).map_err(|_| JsValue::from_str("RSA_PUBLIC_KEY_ERROR"))?;
        Ok(Self {
            inner: RsaBssaPublicKey::new(pk)
        })
    }

    pub fn blind(&self, msg: &[u8]) -> Result<JsBlindResult, JsValue> {
        let mut thread_rng = rand::rng();
        let result = self.inner.blind(&mut thread_rng, msg)?;
        Ok(result.into())
    }
}

