use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use portpicker::pick_unused_port;
use tracing::{debug, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use ledger_lib::{
    info::{ConnInfo, Model as LedgerModel},
    transport::TcpInfo,
    LedgerHandle, LedgerInfo, LedgerProvider, Transport,
};
use ledger_sim::*;

pub mod ui;
pub mod ui_nano;
pub use ui::{ui_for, ui_for_with_screenshots, UiDriver};

const CONNECT_TIMEOUT_S: usize = 10;

/// Resolve the device [Model] under test from the `MODEL` environment
/// variable, defaulting to the nano S plus
pub fn model() -> Model {
    match std::env::var("MODEL").map(|v| Model::from_str(&v)) {
        Ok(Ok(m)) => m,
        Ok(Err(_e)) => panic!("Invalid MODEL"),
        Err(_e) => Model::NanoSP,
    }
}

// Setup speculos instance and TCP connector with an optional seed
pub async fn setup(seed: Option<String>) -> (GenericDriver, GenericHandle, LedgerHandle) {
    // Setup logging
    let log_level = match std::env::var("LOG_LEVEL").map(|v| LevelFilter::from_str(&v)) {
        Ok(Ok(l)) => l,
        _ => LevelFilter::DEBUG,
    };

    // Setup logging
    let filter = EnvFilter::from_default_env()
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("rocket=warn".parse().unwrap())
        .add_directive("btleplug=warn".parse().unwrap())
        .add_directive(log_level.into());

    let _ = FmtSubscriber::builder()
        .compact()
        .without_time()
        .with_max_level(log_level)
        .with_env_filter(filter)
        .try_init();

    // Find open ports
    let http_port = pick_unused_port().unwrap();
    let apdu_port = pick_unused_port().unwrap();

    // Determine model
    let model = model();

    // Fetch simulator mode
    let driver_mode = match std::env::var("DRIVER_MODE").map(|v| DriverMode::from_str(&v)) {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => panic!("Invalid DRIVER_MODE: {e:?}"),
        _ => DriverMode::Docker,
    };

    // Select API level
    // TODO: find a canonical (self-updating?) source for these
    let api_level = match model {
        Model::NanoSP => "26".to_string(),
        Model::NanoX => "26".to_string(),
        // Touch devices are not yet covered by the simulator tests, see
        // `helpers::ui` for the state of the UI drivers
        Model::NanoS | Model::Stax | Model::Flex | Model::NanoGen5 => {
            panic!("unsupported model: {model}")
        }
    };

    println!("Using model: {model} ({driver_mode} driver)");

    // Setup simulator
    let mut speculos_opts = Options {
        http_port,
        apdu_port: Some(apdu_port),
        seed,
        model,
        api_level: Some(api_level),
        // NOTE: speculos defaults to the QT display, which has no X server to
        // connect to under test and takes the simulator down with it.
        display: Some(Display::Headless),
        //trace: true,
        ..Default::default()
    };

    // Setup app path from environment
    let nanoapp_path = std::env::var("NANOAPP").map(PathBuf::from);
    let nanoapp_root = std::env::var("NANOAPP_ROOT")
        .map(PathBuf::from)
        .unwrap_or(PathBuf::from("../fw"));

    let app_path = match (nanoapp_path, model) {
        // If we have a nanoapp env argument, use this directly
        (Ok(v), _) => v,
        // Otherwise look for target dir under NANOAPP_ROOT
        (_, Model::NanoSP) => nanoapp_root.join("target/nanosplus/release/ledger-mob-fw"),
        (_, Model::NanoX) => nanoapp_root.join("target/nanox/release/ledger-mob-fw"),
        _ => unimplemented!("Could not determine nanoapp file"),
    };

    // Check app exists
    if !app_path.is_file() {
        panic!("Could not load app: {}", app_path.display())
    }

    println!("Using firmware image: {}", app_path.display());

    // Setup seed from environment
    if let Ok(seed) = std::env::var("SEED") {
        speculos_opts.seed = Some(seed);
    }

    println!("Using app: {}", app_path.display(),);

    println!("Launching speculos (http port: {http_port} apdu port: {apdu_port})");

    // Start simulator and wait for a moment for launch
    let driver = match driver_mode {
        DriverMode::Local => GenericDriver::Local(LocalDriver::new()),
        DriverMode::Docker => {
            GenericDriver::Docker(DockerDriver::new().expect("Failed to setup docker driver"))
        }
    };
    let s = driver
        .run(app_path.to_str().unwrap(), speculos_opts)
        .await
        .expect("Simulator launch failed");

    // Setup ledger provider and TCP APDU connection info
    let mut provider = LedgerProvider::init().await;
    let info = LedgerInfo {
        model: match model {
            Model::NanoSP => LedgerModel::NanoSPlus,
            Model::NanoX => LedgerModel::NanoX,
            Model::NanoS | Model::Stax | Model::Flex | Model::NanoGen5 => {
                panic!("unsupported model: {model}")
            }
        },
        conn: ConnInfo::Tcp(TcpInfo {
            addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), apdu_port),
        }),
    };

    // Wait so the simulator has a chance to launch
    tokio::time::sleep(Duration::from_secs(3)).await;

    debug!("Connecting TCP APDU transport");

    // Connect to simulator APDU socket
    // This can take a variable amount of time in CI so we retry periodically
    // until the simulator is available.
    let mut device = None;
    for i in 0..CONNECT_TIMEOUT_S {
        // Attempt to connect to simulator
        match provider.connect(info.clone()).await {
            Ok(v) => {
                device = Some(v);
                break;
            }
            Err(_) if i < CONNECT_TIMEOUT_S - 1 => (),
            Err(e) => panic!("Failed to connect APDU socket {e:?}"),
        };

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let device = device.unwrap();

    // Press _something_ to dismiss `Review Pending` message
    for i in 0..CONNECT_TIMEOUT_S {
        match s.button(Button::Right, Action::PressAndRelease).await {
            Ok(_) => break,
            Err(_) if i < CONNECT_TIMEOUT_S - 1 => (),
            Err(e) => panic!("Failed to exit review pending state {e:?}"),
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    (driver, s, device)
}

/// Run unlock UI where required for tests
#[allow(unused)]
pub async fn approve_wallet_sync(h: &GenericHandle) {
    ui_for(model(), h)
        .approve_sync()
        .await
        .expect("wallet sync approval failed");
}

/// Run transaction approval UI where required for tests.
///
/// This walks the approval pages until the approve page is displayed, so it
/// covers both the blind and summary flows and transactions with differing
/// output and total counts.
#[allow(unused)]
pub async fn approve_tx(h: &GenericHandle) {
    ui_for(model(), h)
        .approve_tx()
        .await
        .expect("transaction approval failed");
}

/// [approve_tx], writing a screenshot of each page visited to
/// `../target/ui/<name>.<n>.png`
#[allow(unused)]
pub async fn approve_tx_capture(h: &GenericHandle, name: &str) {
    let prefix = PathBuf::from("../target/ui").join(name);

    ui_for_with_screenshots(model(), h, prefix)
        .approve_tx()
        .await
        .expect("transaction approval failed");
}
