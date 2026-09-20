//! AES-128-GCM, password application configuration.
pub type Cipher = aes_gcm::Aes128Gcm;
pub const APP: solid_core::App = solid_core::App {
    name: "a7",
    algorithm: 3,
    mode: solid_core::Mode::Password,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
