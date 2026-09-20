//! ChaCha20-Poly1305, password application configuration.
pub type Cipher = chacha20poly1305::ChaCha20Poly1305;
pub const APP: solid_core::App = solid_core::App {
    name: "a1",
    algorithm: 1,
    mode: solid_core::Mode::Password,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
