//! AES-256-GCM-SIV, key-file application configuration.
pub type Cipher = aes_gcm_siv::Aes256GcmSiv;
pub const APP: solid_core::App = solid_core::App {
    name: "a17",
    algorithm: 6,
    mode: solid_core::Mode::KeyFile,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
