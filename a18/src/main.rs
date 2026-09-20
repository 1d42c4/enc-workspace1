fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a18::Cipher>(a18::APP, a18::EMBEDDED_KEY)
}
