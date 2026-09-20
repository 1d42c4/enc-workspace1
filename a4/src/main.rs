fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a4::Cipher>(a4::APP, a4::EMBEDDED_KEY)
}
