use crypto_bigint::modular::BoxedMontyForm;
use crypto_bigint::{BoxedUint, CtOption, NonZero, RandomMod};
use rand::RngExt;
use rsa::rand_core::CryptoRng;
use rsa::traits::PublicKeyParts;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindedMessage(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InverseBlindFactor(pub Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Randomizer(pub [u8; 32]);

impl AsRef<[u8]> for BlindedMessage {
    fn as_ref(&self) -> &[u8]{
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for InverseBlindFactor {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for Randomizer {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct BlindResult {
    pub blinded_msg: BlindedMessage,
    pub secret: InverseBlindFactor,
    pub rnd_msg: Option<Randomizer>
}
pub trait MessagePrepare {
    fn prepare<R: CryptoRng + ?Sized>(rng: &mut R) -> Option<Randomizer>;
}

pub struct RandomizedMsg;
impl MessagePrepare for RandomizedMsg {
    fn prepare<R: CryptoRng + ?Sized>(rng: &mut R) -> Option<Randomizer>{
        let mut preffix = [0u8; 32];
        rng.fill(&mut preffix);
        Some(Randomizer(preffix))
    }
}
pub struct DeterministicMsg;
impl MessagePrepare for DeterministicMsg {
    fn prepare<R: CryptoRng + ?Sized>(_rng: &mut R) -> Option<Randomizer>{
        None
    }
}

pub fn blind<Rng: CryptoRng + ?Sized, PK: PublicKeyParts>(
    encoded_message: BoxedUint,
    rng: &mut Rng,
    pk: &PK,
) -> (BoxedUint, BoxedUint) {
    let n: &NonZero<BoxedUint> = pk.n();
    let e: &BoxedUint = pk.e();
    let n_bits = pk.n_bits_precision();

    let mut r: BoxedUint;

    let r_inv = loop {
        r = BoxedUint::random_mod_vartime(rng, n);
        if r.is_zero().into() {
            r = BoxedUint::one_with_precision(n_bits);
        }

        let unblinder: CtOption<BoxedUint> = r.invert_mod(n);
        if let Some(inv) = unblinder.into_option() {
            break inv
        }
    };

    let blind_factor = BoxedMontyForm::new(r, pk.n_params()).pow(e);
    let em_monty = BoxedMontyForm::new(encoded_message, pk.n_params());

    let blinded_message = em_monty.mul(&blind_factor).retrieve();
    (blinded_message, r_inv)
}