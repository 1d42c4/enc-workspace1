fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a2::Cipher>(a2::APP, a2::EMBEDDED_KEY)
}
