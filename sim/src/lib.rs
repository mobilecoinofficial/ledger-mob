// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Wrapper for programmatic Speculos execution using Docker
//!
//! (or a local install if you're into python packaging)
//!

use std::collections::HashMap;

use clap::Parser;

use strum::{Display, EnumString, EnumVariantNames};

mod drivers;
pub use drivers::*;

mod handle;
pub use handle::*;

/// Device model
#[derive(Copy, Clone, PartialEq, Debug, EnumVariantNames, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Model {
    /// Nano S
    NanoS,
    /// Nano S Plus
    #[strum(serialize = "nanosplus", to_string = "nanosp")]
    NanoSP,
    /// Nano X
    NanoX,
}

impl Model {
    /// Fetch target name for a given ledger model
    pub fn target(&self) -> &'static str {
        match self {
            Model::NanoS => "nanos",
            Model::NanoSP => "nanosplus",
            Model::NanoX => "nanox",
        }
    }
}

/// Simulator display mode
#[derive(Copy, Clone, PartialEq, Debug, EnumVariantNames, Display, EnumString, clap::ValueEnum)]
#[strum(serialize_all = "lowercase")]
pub enum Display {
    /// Headless mode
    Headless,
    /// QT based rendering
    Qt,
    /// Text based (command line) rendering
    Text,
}

/// Simulator options
#[derive(Clone, PartialEq, Debug, Parser)]
pub struct Options {
    /// Model to simulate
    #[clap(long, default_value_t = Options::default().model)]
    pub model: Model,

    /// Display mode
    #[clap(long, value_enum, default_value_t = Options::default().display)]
    pub display: Display,

    /// SDK version override (defaults based on --model)
    #[clap(long)]
    pub sdk: Option<String>,

    /// BIP39 seed for initialisation
    #[clap(long, env)]
    pub seed: Option<String>,

    /// Enable HTTP API port
    #[clap(long, default_value_t = Options::default().http_port)]
    pub http_port: u16,

    /// Enable APDU TCP port (usually 1237)
    #[clap(long, env)]
    pub apdu_port: Option<u16>,

    /// Enable debugging and wait for GDB connection (port 1234)
    #[clap(long)]
    pub debug: bool,

    /// Speculos root (used to configure python paths if set)
    #[clap(long, env = "SPECULOS_ROOT")]
    pub root: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            model: Model::NanoSP,
            display: Display::Headless,
            sdk: None,
            seed: None,
            http_port: 5000,
            apdu_port: None,
            debug: false,
            root: None,
        }
    }
}

impl Options {
    /// Build an argument list from [Options]
    pub fn args(&self) -> Vec<String> {
        // Basic args
        let mut args = vec![
            format!("--model={}", self.model),
            format!("--display={}", self.display),
            format!("--api-port={}", self.http_port),
        ];

        if let Some(seed) = &self.seed {
            args.push(format!("--seed={seed}"));
        }

        if let Some(apdu_port) = &self.apdu_port {
            args.push(format!("--apdu-port={apdu_port}"));
        }

        if let Some(sdk) = &self.sdk {
            args.push(format!("--sdk={sdk}"));
        }

        if self.debug {
            args.push("--debug".to_string());
        }

        args
    }

    /// Build environmental variable list from [Options]
    pub fn env(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();

        if let Some(seed) = &self.seed {
            env.insert("SPECULOS_SEED".to_string(), seed.clone());
        }

        env
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::Model;

    #[test]
    fn model_name_encoding() {
        let t = &[
            (Model::NanoS, "nanos", "nanos"),
            (Model::NanoSP, "nanosp", "nanosp"),
            (Model::NanoSP, "nanosp", "nanosplus"),
            (Model::NanoX, "nanox", "nanox"),
        ];

        for (model, enc, dec) in t {
            assert_eq!(&model.to_string(), enc);
            assert_eq!(Ok(*model), Model::from_str(dec));
        }
    }
}
