fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a5::Cipher>(a5::APP, a5::EMBEDDED_KEY)
}
