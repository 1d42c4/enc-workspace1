//! AES-128-GCM, key-file application configuration.
pub type Cipher = aes_gcm::Aes128Gcm;
pub const APP: solid_core::App = solid_core::App {
    name: "a8",
    algorithm: 3,
    mode: solid_core::Mode::KeyFile,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
