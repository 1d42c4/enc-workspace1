//! AES-128-GCM-SIV, key-file application configuration.
pub type Cipher = aes_gcm_siv::Aes128GcmSiv;
pub const APP: solid_core::App = solid_core::App {
    name: "a14",
    algorithm: 5,
    mode: solid_core::Mode::KeyFile,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
