//! AES-256-GCM, embedded-key application configuration.
pub type Cipher = aes_gcm::Aes256Gcm;
pub const APP: solid_core::App = solid_core::App {
    name: "a12",
    algorithm: 4,
    mode: solid_core::Mode::Embedded,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = Some(&[
    228, 117, 60, 43, 143, 147, 74, 211, 142, 145, 187, 130, 204, 243, 122, 254, 76, 223, 79, 201,
    122, 90, 248, 235, 212, 137, 184, 86, 156, 232, 172, 5,
]);
