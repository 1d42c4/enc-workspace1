fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a14::Cipher>(a14::APP, a14::EMBEDDED_KEY)
}
