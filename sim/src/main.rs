// Copyright (c) 2022-2023 The MobileCoin Foundation

use clap::Parser;
use log::{debug, info, LevelFilter};

use ledger_sim::*;

/// Ledger Speculos simulator wrapper tool
///
/// This calls out to Docker or a local Speculos.py install
/// to provide a simple way of executing speculos via (this) CLI
/// or rust library (https://docs.rs/ledger-sim).
#[derive(Clone, Debug, PartialEq, Parser)]
pub struct Args {
    /// Application to run
    app: String,

    /// Driver mode
    #[clap(long, value_enum, default_value = "docker")]
    driver: DriverMode,

    #[clap(flatten)]
    speculos_opts: Options,

    /// Log level
    #[clap(long, default_value = "debug")]
    log_level: LevelFilter,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    info!("Launching speculos...");

    // Setup logging
    let mut c = simplelog::ConfigBuilder::new();
    c.add_filter_ignore_str("bollard");
    c.add_filter_allow_str("ledger_sim::drivers::docker");

    let _ = simplelog::SimpleLogger::init(args.log_level, c.build());

    // Run with specified driver
    match args.driver {
        DriverMode::Local => {
            let d = LocalDriver::new();
            run_simulator(d, &args.app, args.speculos_opts).await?;
        }
        DriverMode::Docker => {
            let d = DockerDriver::new()?;
            run_simulator(d, &args.app, args.speculos_opts).await?;
        }
    }

    Ok(())
}

async fn run_simulator<D: Driver>(driver: D, app: &str, opts: Options) -> anyhow::Result<()> {
    // Start simulator
    let mut h = driver.run(app, opts).await?;

    // Await simulator exit or exit signal
    tokio::select!(
        // Await simulator task completion
        _ = driver.wait(&mut h) => {
            debug!("Complete!");
        }
        // Exit on ctrl + c
        _ = tokio::signal::ctrl_c() => {
            debug!("Exit!");
            driver.exit(h).await?;
        },
    );

    Ok(())
}
