fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a16::Cipher>(a16::APP, a16::EMBEDDED_KEY)
}
