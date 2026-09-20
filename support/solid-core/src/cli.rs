use crate::{
    App, Credential, Mode, Result, decrypt, encrypt, generate_key, read_key, read_password,
};
use aead::{AeadInPlace, KeyInit};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::{io, path::PathBuf, process::ExitCode};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Authenticated file encryption. Input is retained; existing output is never replaced."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt INPUT to a new OUTPUT file.
    Encrypt(Files),
    /// Verify and decrypt INPUT to a new OUTPUT file.
    Decrypt(Files),
    /// Generate a random 32-byte key file (key-file apps only).
    Keygen { output: PathBuf },
}

#[derive(Args)]
struct Files {
    input: PathBuf,
    output: PathBuf,
    /// A raw 32-byte secret key (required by key-file apps).
    #[arg(long, conflicts_with = "password_file")]
    key: Option<PathBuf>,
    /// Read a one-line UTF-8 password from a file; otherwise prompt without echo.
    #[arg(long)]
    password_file: Option<PathBuf>,
}

fn usage(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn execute<C: AeadInPlace + KeyInit>(
    app: App,
    embedded: Option<&[u8; 32]>,
    command: Command,
) -> Result<()> {
    let (files, encrypting) = match command {
        Command::Keygen { output } => {
            if app.mode != Mode::KeyFile {
                return Err(usage("keygen is available only in key-file apps"));
            }
            return generate_key(&output);
        }
        Command::Encrypt(files) => (files, true),
        Command::Decrypt(files) => (files, false),
    };
    let key;
    let password;
    let credential = match app.mode {
        Mode::Password => {
            if files.key.is_some() {
                return Err(usage("password apps do not accept --key"));
            }
            password = if let Some(path) = files.password_file {
                read_password(&path)?
            } else {
                let first = Zeroizing::new(rpassword::prompt_password("Password: ")?);
                if encrypting {
                    let second = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
                    if *first != *second {
                        return Err(usage("passwords do not match"));
                    }
                }
                Zeroizing::new(first.as_bytes().to_vec())
            };
            Credential::Password(&password)
        }
        Mode::KeyFile => {
            if files.password_file.is_some() {
                return Err(usage("key-file apps do not accept --password-file"));
            }
            key =
                read_key(&files.key.ok_or_else(|| {
                    usage("this app requires --key KEYFILE; create it with keygen")
                })?)?;
            Credential::Key(&key)
        }
        Mode::Embedded => {
            if files.key.is_some() || files.password_file.is_some() {
                return Err(usage("embedded-key apps do not accept credential options"));
            }
            Credential::Embedded(embedded.ok_or_else(|| usage("missing embedded key"))?)
        }
    };
    if encrypting {
        encrypt::<C>(app, credential, &files.input, &files.output)
    } else {
        decrypt::<C>(app, credential, &files.input, &files.output)
    }
}

/// Run the shared CLI with this binary's fixed algorithm, mode, and optional public key.
pub fn run<C: AeadInPlace + KeyInit>(app: App, embedded: Option<&[u8; 32]>) -> ExitCode {
    if app.mode == Mode::Embedded {
        eprintln!(
            "PUBLIC EMBEDDED KEY: anyone with this app or source can decrypt and forge these files. Informal use only."
        );
    }
    let matches = Cli::command().name(app.name).get_matches();
    let cli = Cli::from_arg_matches(&matches).expect("clap validated the arguments");
    match execute::<C>(app, embedded, cli.command) {
        Ok(()) => {
            println!("Done. Source retained.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {error}", app.name);
            ExitCode::FAILURE
        }
    }
}
