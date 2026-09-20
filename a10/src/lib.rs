//! AES-256-GCM, password application configuration.
pub type Cipher = aes_gcm::Aes256Gcm;
pub const APP: solid_core::App = solid_core::App {
    name: "a10",
    algorithm: 4,
    mode: solid_core::Mode::Password,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
