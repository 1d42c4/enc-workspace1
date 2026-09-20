//! AES-256-GCM-SIV, embedded-key application configuration.
pub type Cipher = aes_gcm_siv::Aes256GcmSiv;
pub const APP: solid_core::App = solid_core::App {
    name: "a18",
    algorithm: 6,
    mode: solid_core::Mode::Embedded,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = Some(&[
    174, 37, 13, 213, 209, 143, 27, 3, 89, 105, 9, 5, 137, 94, 75, 147, 57, 143, 6, 171, 120, 114,
    214, 223, 119, 255, 157, 158, 79, 153, 213, 189,
]);
