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
        let e = BoxedUint::from(65537u32);
        let n: BoxedUint = BoxedUint::from_be_hex("aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5", 4096).unwrap();

        let pk: RsaPublicKey = RsaPublicKey::new(n, e).map_err(|_| JsValue::from_str("RSA_PUBLIC_KEY_ERROR"))?;
        Ok(Self {
            inner: RsaBssaPublicKey::new(pk)
        })
    }
}

