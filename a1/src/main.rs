fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a1::Cipher>(a1::APP, a1::EMBEDDED_KEY)
}
