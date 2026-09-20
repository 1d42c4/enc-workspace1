fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a10::Cipher>(a10::APP, a10::EMBEDDED_KEY)
}
