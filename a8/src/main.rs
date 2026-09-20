fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a8::Cipher>(a8::APP, a8::EMBEDDED_KEY)
}
