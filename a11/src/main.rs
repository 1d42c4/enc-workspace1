fn main() -> std::process::ExitCode {
    solid_core::cli::run::<a11::Cipher>(a11::APP, a11::EMBEDDED_KEY)
}
