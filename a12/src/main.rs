fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a12::Cipher>(a12::APP, a12::EMBEDDED_KEY)
}
