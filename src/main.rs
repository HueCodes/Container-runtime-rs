use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate_runtime::container::ContainerBuilder;

#[derive(Parser)]
#[command(name = "crate")]
#[command(author = "Hugh")]
#[command(version = "0.1.0")]
#[command(about = "A minimal OCI-compatible container runtime", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command in a new container
    Run {
        /// Command to run inside the container
        #[arg(required = true)]
        command: Vec<String>,

        /// Set container hostname
        #[arg(short = 'H', long, default_value = "container")]
        hostname: String,

        /// Root filesystem path (uses temporary if not specified)
        #[arg(short, long)]
        rootfs: Option<String>,
    },

    /// Initialize container (internal use)
    #[command(hide = true)]
    Init {
        /// Command to run
        #[arg(required = true)]
        command: Vec<String>,

        /// Hostname
        #[arg(long)]
        hostname: String,

        /// Rootfs path
        #[arg(long)]
        rootfs: String,
    },
}

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("crate_runtime=info".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            command,
            hostname,
            rootfs,
        } => {
            tracing::info!("Starting container with command: {:?}", command);

            let mut builder = ContainerBuilder::new()
                .command(command)
                .hostname(hostname);

            if let Some(rootfs_path) = rootfs {
                builder = builder.rootfs(rootfs_path);
            }

            let container = builder.build()?;
            let exit_code = container.run()?;

            std::process::exit(exit_code);
        }

        Commands::Init {
            command,
            hostname,
            rootfs,
        } => {
            // This is called inside the container namespace
            crate_runtime::container::init_container(&command, &hostname, &rootfs)?;
            Ok(())
        }
    }
}
