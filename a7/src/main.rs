fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a7::Cipher>(a7::APP, a7::EMBEDDED_KEY)
}
