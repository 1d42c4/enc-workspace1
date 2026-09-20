fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a6::Cipher>(a6::APP, a6::EMBEDDED_KEY)
}
