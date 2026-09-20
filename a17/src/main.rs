fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a17::Cipher>(a17::APP, a17::EMBEDDED_KEY)
}
