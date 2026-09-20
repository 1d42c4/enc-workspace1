//! XChaCha20-Poly1305, embedded-key application configuration.
pub type Cipher = chacha20poly1305::XChaCha20Poly1305;
pub const APP: solid_core::App = solid_core::App {
    name: "a6",
    algorithm: 2,
    mode: solid_core::Mode::Embedded,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = Some(&[
    109, 199, 43, 144, 10, 246, 156, 169, 246, 72, 1, 14, 177, 195, 225, 4, 89, 80, 216, 28, 206,
    59, 90, 243, 254, 65, 159, 92, 238, 222, 250, 239,
]);
