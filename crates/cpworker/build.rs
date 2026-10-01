//! Build guard for the optional `dpdk` feature.
//!
//! The default build has no DPDK dependency. Enabling `--features dpdk` makes
//! the capturer link against the DPDK runtime libraries; this script checks
//! that they are actually present *before* rustc gets a chance to emit a wall
//! of undefined-symbol errors, and points at the install guide instead.
//!
//! The check is deliberately the same one the upstream CMake build uses:
//! `pkg_check_modules(LIBDPDK REQUIRED libdpdk)` (`cpworker/CMakeLists.txt`).
//!
//! Escape hatch: `CPRS_DPDK_ALLOW_MISSING=1` lets a *compile check*
//! (`cargo check --features dpdk`) proceed without DPDK. It is not a supported
//! way to produce a binary — without the libraries nothing will link.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CPRS_DPDK_ALLOW_MISSING");
    println!("cargo:rerun-if-env-changed=CPRS_DPDK_STATIC");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    if std::env::var_os("CARGO_FEATURE_DPDK").is_none() {
        // Default build: no DPDK, no link flags, nothing to check.
        return;
    }

    let version = pkg_config(&["--modversion", "libdpdk"]);
    let libs = match version {
        Ok(version) => {
            println!("cargo:warning=building cpworker with DPDK {version}");
            let mut args = vec!["--libs", "libdpdk"];
            if std::env::var_os("CPRS_DPDK_STATIC").is_some() {
                args.push("--static");
            }
            match pkg_config(&args) {
                Ok(libs) => libs,
                Err(err) => {
                    return missing_dpdk(&err);
                }
            }
        }
        Err(err) => return missing_dpdk(&err),
    };

    // Emit every pkg-config token as a raw linker argument, preserving order
    // (pkg-config emits `-L` before `-l`, and whole-archive wrappers in order
    // for a static link).
    for token in libs.split_whitespace() {
        if token.starts_with('-') {
            println!("cargo:rustc-link-arg={token}");
        }
    }
}

/// Run `pkg-config` and return its stdout, or an error describing why it
/// could not be run / exited nonzero.
fn pkg_config(args: &[&str]) -> Result<String, String> {
    let out = Command::new("pkg-config")
        .args(args)
        .output()
        .map_err(|e| format!("could not run `pkg-config {}`: {e}", args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "`pkg-config {}` failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Report a missing/unusable DPDK, unless the compile-check escape hatch is set.
fn missing_dpdk(reason: &str) {
    if std::env::var_os("CPRS_DPDK_ALLOW_MISSING").is_some() {
        println!(
            "cargo:warning=DPDK not found ({reason}); continuing because \
             CPRS_DPDK_ALLOW_MISSING is set (compile check only — the binary \
             will not link)"
        );
        return;
    }
    panic!(
        "\n\
         cpworker was built with `--features dpdk`, but DPDK was not found.\n\
         \n\
         Reason: {reason}\n\
         \n\
         The DPDK pdump capturer needs the DPDK development files and the\n\
         pkg-config module `libdpdk` (upstream pins v22.11; see\n\
         cpworker/docs/install_dpdk.md in the reference tree). Install DPDK\n\
         such that `pkg-config --modversion libdpdk` succeeds, or rebuild\n\
         without the feature:\n\
         \n\
             cargo build -p cpworker            # no DPDK needed\n\
         \n\
         For a compile-only check without DPDK, set CPRS_DPDK_ALLOW_MISSING=1\n\
         (it cannot produce a runnable binary).\n"
    );
}
