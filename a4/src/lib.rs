//! XChaCha20-Poly1305, password application configuration.
pub type Cipher = chacha20poly1305::XChaCha20Poly1305;
pub const APP: solid_core::App = solid_core::App {
    name: "a4",
    algorithm: 2,
    mode: solid_core::Mode::Password,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = None;
