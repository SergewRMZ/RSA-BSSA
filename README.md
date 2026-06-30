# RSA-BSSA
An RSA-based Blind Signature Cryptographic Scheme developed in Rust and and compiled as a WebAssembly library.
This library implements secure blind signature protocols—specifically utilizing RSA-PSS (`emsa_pss`), Mask Generation Functions (`mgf1`), and arbitrary-precision arithmetic (`crypto-bigint`)—tailored for distributed environments such as electronic voting systems (e-voting) where voter privacy and untraceability are paramount.
