use rsa::{BoxedUint, RsaPublicKey};
use sha3::Sha3_384;
use wasm_bindgen::prelude::*;

use crate::{key_pair::{RsaBssaError, RsaBssaPublicKey}};
use crate::rsa_bssa::RandomizedMsg;
mod mgf1;
mod emsa_pss;
mod rsa_bssa;
pub mod key_pair;

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
struct WasmRsaBssa {
    inner: RsaBssaPublicKey<Sha3_384, RandomizedMsg>,
}

#[wasm_bindgen]
impl WasmRsaBssa {
    #[wasm_bindgen(constructor)]
    pub fn new(n_bytes: &[u8], e_bytes: &[u8]) -> Result<WasmRsaBssa, JsValue>{
        let n = BoxedUint::from_be_slice_vartime(n_bytes);
        let e = BoxedUint::from_be_slice_vartime(e_bytes);
        let pk: RsaPublicKey = RsaPublicKey::new(n, e).map_err(|_| JsValue::from_str("RSA_PUBLIC_KEY_ERROR"))?;
        Ok(Self {
            inner: RsaBssaPublicKey::new(pk)
        })
    }
}

