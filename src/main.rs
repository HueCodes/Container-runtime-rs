use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate_runtime::config::RuntimeConfig;
use crate_runtime::container::ContainerBuilder;

#[derive(Parser)]
#[command(name = "crate")]
#[command(author = "Hugh")]
#[command(version = "0.1.0")]
#[command(about = "A minimal OCI-compatible container runtime", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to config file
    #[arg(long, global = true)]
    config: Option<String>,

    /// Runtime root directory
    #[arg(long, global = true, default_value = "/run/crate")]
    root: String,
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

        /// Memory limit (e.g., 512m, 1g)
        #[arg(long)]
        memory: Option<String>,

        /// CPU quota in microseconds per 100ms period
        #[arg(long)]
        cpu_quota: Option<u64>,

        /// PID limit
        #[arg(long)]
        pids_limit: Option<u64>,

        /// Enable networking
        #[arg(long, default_value_t = false)]
        net: bool,

        /// Read-only root filesystem
        #[arg(long, default_value_t = false)]
        read_only: bool,
    },

    /// Create a container from an OCI bundle
    Create {
        /// Container ID
        container_id: String,

        /// Path to the OCI bundle directory
        #[arg(short, long)]
        bundle: String,
    },

    /// Start a created container
    Start {
        /// Container ID
        container_id: String,
    },

    /// Stop a running container
    Stop {
        /// Container ID
        container_id: String,

        /// Signal to send (default: SIGTERM)
        #[arg(short, long, default_value = "SIGTERM")]
        signal: String,

        /// Timeout in seconds before SIGKILL
        #[arg(short, long, default_value_t = 10)]
        timeout: u64,
    },

    /// Delete a stopped container
    Delete {
        /// Container ID
        container_id: String,
    },

    /// Query container state
    State {
        /// Container ID
        container_id: String,
    },

    /// List all containers
    List,

    /// Execute a command in a running container
    Exec {
        /// Container ID
        container_id: String,

        /// Command to execute
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Pull an image from a registry
    Pull {
        /// Image reference (e.g., alpine:latest, ubuntu:22.04)
        image: String,
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
    let cli = Cli::parse();

    // Load configuration
    let config = if let Some(ref path) = cli.config {
        RuntimeConfig::load_from(std::path::Path::new(path)).map_err(|e| anyhow::anyhow!(e))?
    } else {
        RuntimeConfig::load()
    };

    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env().add_directive(config.log.level.parse().unwrap_or_else(
                |_| {
                    "crate_runtime=info"
                        .parse()
                        .expect("valid default directive")
                },
            )),
        )
        .init();

    match cli.command {
        Commands::Run {
            command,
            hostname,
            rootfs,
            memory: _,
            cpu_quota: _,
            pids_limit: _,
            net: _,
            read_only: _,
        } => {
            tracing::info!(
                command = ?command,
                hostname = %hostname,
                "Starting container"
            );

            let mut builder = ContainerBuilder::new().command(command).hostname(hostname);

            if let Some(rootfs_path) = rootfs {
                builder = builder.rootfs(rootfs_path);
            }

            let container = builder.build()?;
            let exit_code = container.run()?;

            std::process::exit(exit_code);
        }

        Commands::Create {
            container_id,
            bundle,
        } => {
            tracing::info!(
                container_id = %container_id,
                bundle = %bundle,
                "Creating container"
            );
            let root = std::path::PathBuf::from(&cli.root);
            let rt = crate_runtime::runtime::RuntimeManager::new(root);
            let status = rt.create(&container_id, std::path::Path::new(&bundle))?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }

        Commands::Start { container_id } => {
            tracing::info!(container_id = %container_id, "Starting container");
            let root = std::path::PathBuf::from(&cli.root);
            let rt = crate_runtime::runtime::RuntimeManager::new(root);
            rt.start(&container_id)?;
        }

        Commands::Stop {
            container_id,
            signal: _,
            timeout,
        } => {
            tracing::info!(container_id = %container_id, "Stopping container");
            let root = std::path::PathBuf::from(&cli.root);
            let rt = crate_runtime::runtime::RuntimeManager::new(root);
            rt.stop(
                &container_id,
                None,
                Some(std::time::Duration::from_secs(timeout)),
            )?;
        }

        Commands::Delete { container_id } => {
            tracing::info!(container_id = %container_id, "Deleting container");
            let root = std::path::PathBuf::from(&cli.root);
            let rt = crate_runtime::runtime::RuntimeManager::new(root);
            rt.delete(&container_id)?;
        }

        Commands::State { container_id } => {
            let root = std::path::PathBuf::from(&cli.root);
            let rt = crate_runtime::runtime::RuntimeManager::new(root);
            let status = rt.state(&container_id)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }

        Commands::List => {
            let root = std::path::PathBuf::from(&cli.root);
            let rt = crate_runtime::runtime::RuntimeManager::new(root);
            let containers = rt.list()?;
            if containers.is_empty() {
                println!("No containers found.");
            } else {
                println!("{:<14} {:<10} {:<8} BUNDLE", "ID", "STATE", "PID");
                for c in &containers {
                    println!(
                        "{:<14} {:<10} {:<8} {}",
                        c.id,
                        format!("{}", c.state),
                        c.pid.map_or("-".to_string(), |p| p.to_string()),
                        c.bundle.display()
                    );
                }
            }
        }

        Commands::Exec {
            container_id,
            command,
        } => {
            tracing::info!(
                container_id = %container_id,
                command = ?command,
                "Exec into container"
            );
            eprintln!(
                "exec into container {} with {:?} (not yet implemented for running containers)",
                container_id, command
            );
        }

        Commands::Pull { image } => {
            tracing::info!(image = %image, "Pulling image");
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let reference = crate_runtime::image::ImageReference::parse(&image)?;
                let store = crate_runtime::image::ImageStore::new(config.image_root.clone());
                let manifest = store.pull_image(&reference).await?;
                println!("Pulled {} ({} layers)", image, manifest.layers.len());
                crate_runtime::Result::Ok(())
            })?;
        }

        Commands::Init {
            command,
            hostname,
            rootfs,
        } => {
            crate_runtime::container::init_container(&command, &hostname, &rootfs)?;
        }
    }

    Ok(())
}
