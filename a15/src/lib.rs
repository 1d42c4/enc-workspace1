//! AES-128-GCM-SIV, embedded-key application configuration.
pub type Cipher = aes_gcm_siv::Aes128GcmSiv;
pub const APP: solid_core::App = solid_core::App {
    name: "a15",
    algorithm: 5,
    mode: solid_core::Mode::Embedded,
};
pub const EMBEDDED_KEY: Option<&[u8; 32]> = Some(&[
    52, 194, 171, 253, 48, 161, 70, 132, 227, 42, 49, 15, 217, 67, 100, 139, 254, 133, 34, 121,
    167, 167, 79, 134, 240, 53, 252, 125, 105, 200, 29, 197,
]);
