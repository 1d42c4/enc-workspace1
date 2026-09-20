//! AES-128-GCM, embedded-key application configuration.
pub type Cipher = aes_gcm::Aes128Gcm;
pub const APP: solid_core::App = solid_core::App {
    name: "a9",
    algorithm: 3,
    mode: solid_core::Mode::Embedded,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = Some(&[
    21, 112, 102, 101, 239, 117, 220, 1, 23, 96, 127, 211, 122, 170, 16, 170, 7, 178, 102, 28, 245,
    238, 118, 63, 163, 215, 253, 34, 103, 154, 157, 125,
]);
