use anyhow::{anyhow, Context};
use quote::quote;
use std::{env, path::PathBuf};

fn main() -> anyhow::Result<()> {
    // Rebuild on linker script changes
    println!("cargo:rerun-if-changed=script.ld");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
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

    // Copy the app icon to the build dir
    copy_app_icon()?;

    // Process image files
    for i in IMAGES {
        process_image(i)?;
    }

    Ok(())
}

/// Copy the install icon declared in `[package.metadata.ledger.<device>]` to the build
/// output dir, under both its own name and the device-independent alias `app_icon.gif`.
///
/// The alias is what `make package-%` and CI packaging consume, so neither needs to carry
/// its own copy of the device -> icon mapping.
fn copy_app_icon() -> anyhow::Result<()> {
    let device = env::var("CARGO_CFG_TARGET_OS").context("CARGO_CFG_TARGET_OS not set")?;

    let icon = app_icon_path(&device)?;
    let src = PathBuf::from(&icon);

    if !src.is_file() {
        return Err(anyhow!(
            "install icon `{icon}` declared in [package.metadata.ledger.{device}] does not exist under {}",
            env::current_dir()?.display(),
        ));
    }
    println!("cargo:rerun-if-changed={icon}");

    let out_dir = get_output_dir();
    let name = src
        .file_name()
        .ok_or_else(|| anyhow!("icon path has no file name: {icon}"))?;

    std::fs::copy(&src, out_dir.join(name))
        .with_context(|| format!("copying {} to {}", src.display(), out_dir.display()))?;
    std::fs::copy(&src, out_dir.join("app_icon.gif"))
        .with_context(|| format!("copying {} to app_icon.gif", src.display()))?;

    Ok(())
}

/// Images to be included in binary
const IMAGES: &[&str] = &["mob14x14.gif", "mob16x16.gif", "mob32x32.gif"];

/// Process an image file to a Glyph object for inclusion
fn process_image(f: &str) -> anyhow::Result<()> {
    let fw_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap()
        .join("assets");

    // Load image and convert to greyscale
    let img = match image::io::Reader::open(fw_dir.join(f)) {
        Ok(v) => v.decode()?,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to open image file '{}': {:?}",
                f,
                e
            ))
        }
    };
    let img = img.into_luma8();

    // Compute dimensions
    // TODO: non %8 dimensions
    let d = img.dimensions();
    let (w, h) = (d.0 as usize, d.1 as usize);
    let s = w * h / 8;

    // Generate buffer
    let mut buff = vec![0u8; s];
    for y in 0..h {
        for x in 0..w {
            let i = y * w + x;
            let p = img.get_pixel(x as u32, y as u32);

            if p.0[0] == 0 {
                buff[i / 8] |= 1 << (i % 8);
            }
        }
    }

    // Generate object to write out
    let o = quote! {
        Glyph::new(&[
            #(#buff),*
            ], #w as u32, #h as u32 )
    };

    // Write out source object
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    std::fs::write(out_path.join(f), o.to_string())?;

    Ok(())
}

/// Read `package.metadata.ledger.<device>.icon` from this crate's manifest, the same
/// table `ledger_device_sdk`'s build script reads to generate the install parameters.
fn app_icon_path(device: &str) -> anyhow::Result<String> {
    let manifest: toml::Value = std::fs::read_to_string("Cargo.toml")
        .context("reading Cargo.toml")?
        .parse()
        .context("parsing Cargo.toml")?;

    manifest
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("ledger"))
        .and_then(|l| l.get(device))
        .and_then(|d| d.get("icon"))
        .and_then(|i| i.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing `package.metadata.ledger.{device}.icon` in fw/Cargo.toml"))
}

fn get_output_dir() -> PathBuf {
    let mut out_path = env::var("OUT_DIR").map(PathBuf::from).unwrap();

    out_path.pop();
    out_path.pop();
    out_path.pop();

    out_path
}
