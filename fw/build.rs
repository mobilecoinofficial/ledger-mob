use std::{env, path::PathBuf};

fn main() -> anyhow::Result<()> {
    // Rebuild on linker script changes
    println!("cargo:rerun-if-changed=script.ld");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=VERSION");
    println!("cargo:rerun-if-env-changed=CI_SHA_SHORT");

    let _target = std::env::var("TARGET").unwrap();

    // Check if we have an injected app version
    let version_tag = match std::env::var("VERSION") {
        Ok(v) => v,
        // Otherwise, run `git describe`
        _ => {
            let output = std::process::Command::new("git")
                .args(["describe", "--dirty=+", "--always"])
                .output()
                .expect("git describe failed");

            std::str::from_utf8(&output.stdout)
                .unwrap()
                .trim()
                .to_string()
        }
    };

    // Load git firmware description and export into environment
    println!("cargo:rustc-env=GIT_TAG={version_tag}");

    let build_time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    println!("cargo:rustc-env=BUILD_TIME={build_time}");

    // Copy icons to build dir
    copy_icons()?;

    Ok(())
}

/// Copy icons to build output dir
fn copy_icons() -> anyhow::Result<()> {
    let out_dir = get_output_dir();

    let images = &["mob14x14i.gif", "mob16x16i.gif", "mob32x32.gif"];

    for i in images {
        std::fs::copy(PathBuf::from("assets").join(i), out_dir.join(i))?;
    }

    Ok(())
}

fn get_output_dir() -> PathBuf {
    let mut out_path = env::var("OUT_DIR").map(PathBuf::from).unwrap();

    out_path.pop();
    out_path.pop();
    out_path.pop();

    out_path
}
