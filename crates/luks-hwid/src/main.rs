mod enroll;
mod error;
mod fsm;
mod keyscript;
mod kmsg;
mod luks;
mod rescue;
mod status;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use luks_hwid_core::KdfParams;

#[derive(Parser)]
#[command(
    name = "luks-hwid",
    version,
    about = "Déverrouillage LUKS par empreinte matérielle (k parmi n), pour machines sans TPM"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enrôle l'empreinte de cette machine dans un volume LUKS2.
    /// Refuse si le volume n'a pas déjà une passphrase de secours.
    Enroll {
        #[arg(long)]
        device: PathBuf,
        /// Header détaché (mode recommandé : le header vit sur la clé USB).
        #[arg(long)]
        header: Option<PathBuf>,
        /// Seuil k. Défaut : max(2, n-1).
        #[arg(long)]
        threshold: Option<u8>,
        /// Mémoire Argon2id en KiB.
        #[arg(long, default_value_t = 65536)]
        m_cost_kib: u32,
        /// Itérations Argon2id.
        #[arg(long, default_value_t = 3)]
        t_cost: u32,
        /// Parallélisme Argon2id.
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    },
    /// Confronte le token luks-hwid au matériel courant (lecture seule).
    Status {
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        header: Option<PathBuf>,
    },
    /// Contrat keyscript crypttab : clé sur stdout, variables CRYPTTAB_*.
    /// Détecté automatiquement quand CRYPTTAB_SOURCE est présent.
    Keyscript,
}

fn main() -> ExitCode {
    // Les Drop (zeroize) s'exécutent à l'unwind ; on journalise juste le
    // panic dans kmsg pour qu'un échec au boot laisse une trace.
    std::panic::set_hook(Box::new(|info| {
        kmsg::Log::new().err(&format!("panic : {info}"));
    }));

    // Invocation keyscript par cryptsetup : argv[1] est la colonne "key"
    // de crypttab (souvent "none"), pas une sous-commande. L'environnement
    // CRYPTTAB_* fait foi.
    let argv1 = std::env::args().nth(1);
    let is_subcommand = matches!(argv1.as_deref(), Some("enroll" | "status" | "keyscript"));
    if std::env::var_os("CRYPTTAB_SOURCE").is_some() && !is_subcommand {
        return ExitCode::from(keyscript::run());
    }

    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Keyscript => keyscript::run(),
        Cmd::Status { device, header } => unwrap_or_report(status::run(device, header)),
        Cmd::Enroll {
            device,
            header,
            threshold,
            m_cost_kib,
            t_cost,
            parallelism,
        } => unwrap_or_report(enroll::run(enroll::EnrollOpts {
            device,
            header,
            threshold,
            kdf: KdfParams {
                algo: "argon2id".to_owned(),
                m_cost_kib,
                t_cost,
                parallelism,
            },
        })),
    };
    ExitCode::from(code)
}

fn unwrap_or_report(res: error::Result<u8>) -> u8 {
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("luks-hwid : {e}");
            1
        }
    }
}
