fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a9::Cipher>(a9::APP, a9::EMBEDDED_KEY)
}
