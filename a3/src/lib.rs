//! ChaCha20-Poly1305, embedded-key application configuration.
pub type Cipher = chacha20poly1305::ChaCha20Poly1305;
pub const APP: solid_core::App = solid_core::App {
    name: "a3",
    algorithm: 1,
    mode: solid_core::Mode::Embedded,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = Some(&[
    153, 130, 185, 176, 99, 134, 185, 92, 252, 247, 239, 208, 202, 174, 112, 130, 106, 26, 63, 51,
    167, 155, 18, 92, 172, 154, 195, 46, 70, 27, 223, 196,
]);
