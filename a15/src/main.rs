fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a15::Cipher>(a15::APP, a15::EMBEDDED_KEY)
}
