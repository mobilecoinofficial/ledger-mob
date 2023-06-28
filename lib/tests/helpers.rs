use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use log::{debug, LevelFilter};
use portpicker::pick_unused_port;
use simplelog::SimpleLogger;

use ledger_lib::{
    transport::{GenericDevice, TcpInfo, TcpTransport},
    Transport,
};
use ledger_sim::*;

// Setup speculos instance and TCP connector with an optional seed
pub async fn setup(seed: Option<String>) -> (GenericDriver, GenericHandle, GenericDevice) {
    // Setup logging
    let log_level = match std::env::var("LOG_LEVEL").map(|v| LevelFilter::from_str(&v)) {
        Ok(Ok(l)) => l,
        _ => LevelFilter::Debug,
    };

    let log_cfg = simplelog::ConfigBuilder::new()
        .add_filter_ignore_str("bollard")
        .add_filter_ignore_str("reqwest")
        .build();

    let _ = SimpleLogger::init(log_level, log_cfg);

    // Find open ports
    let http_port = pick_unused_port().unwrap();
    let apdu_port = pick_unused_port().unwrap();

    // Determine model
    let model = match std::env::var("MODEL").map(|v| Model::from_str(&v)) {
        Ok(Ok(m)) => m,
        Ok(Err(_e)) => panic!("Invalid MODEL"),
        Err(_e) => Model::NanoSP,
    };

    // Fetch simulator mode
    let driver_mode = match std::env::var("DRIVER_MODE").map(|v| DriverMode::from_str(&v)) {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => panic!("Invalid DRIVER_MODE: {e:?}"),
        _ => DriverMode::Docker,
    };

    // Select API level
    // TODO: find a canonical source for these
    let api_level = match model {
        Model::NanoSP => "1".to_string(),
        Model::NanoX => "5".to_string(),
        Model::NanoS => panic!("unsupported model"),
    };

    println!("Using model: {model} ({driver_mode} driver)");

    // Setup simulator
    let mut speculos_opts = Options {
        http_port,
        apdu_port: Some(apdu_port),
        seed,
        model,
        api_level: Some(api_level),
        //trace: true,
        //display: Display::Headless,
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

    // Wait for sim to start listening
    // TODO: this needs to be a while for CI but is very quick locally...
    // could be a retry loop instead of worst-case blocking?
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Setup ADPU connector
    let info = TcpInfo {
        addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), apdu_port),
    };

    // Connect to simulator APDU socket
    debug!("Connecting TCP APDU transport");
    let mut t = TcpTransport::new().expect("APDU connection failed");

    let device = t.connect(info).await.unwrap();

    // Press _something_ to dismiss `Review Pending` message
    // TODO: remove this from reviewed code? feature gate perhaps?
    {
        s.button(Button::Right, Action::PressAndRelease)
            .await
            .expect("Failed to exit review pending");

        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    (driver, s, device.into())
}

/// Run unlock UI where required for tests
#[allow(unused)]
pub async fn approve_wallet_sync(h: &GenericHandle) {
    debug!("UI: Unlock");

    let buttons = &[
        // Right button to move from info to allow
        Button::Right,
        // Both buttons to select allow
        Button::Both,
    ];

    for b in buttons {
        h.button(*b, Action::PressAndRelease).await.unwrap();
    }
}

/// Run transaction approval UI where required for tests
// TODO: this will change with TxSummary support
#[allow(unused)]
pub async fn approve_tx_blind(h: &GenericHandle) {
    debug!("UI: Approve");

    // TODO: we could pull events / screenshots to check we're in the right place?

    let buttons = &[
        // Right button to move to warning screen
        Button::Right,
        // Right button to move to hash screen
        Button::Right,
        // Right button to move to allow screen
        Button::Right,
        // Both buttons to select allow
        Button::Both,
    ];

    for b in buttons {
        h.button(*b, Action::PressAndRelease).await.unwrap();
    }
}
