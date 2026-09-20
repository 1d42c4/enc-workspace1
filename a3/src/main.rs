fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a3::Cipher>(a3::APP, a3::EMBEDDED_KEY)
}
