fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a13::Cipher>(a13::APP, a13::EMBEDDED_KEY)
}
