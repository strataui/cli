//! Cross-platform build runner driving native and web targets.

use std::fs;
use std::path::{Path, PathBuf};
use strata_codegen_js::prelude::*;
use strata_dom::{NodeBlueprint, Tag};

use crate::args::BuildTarget;
use crate::config::StrataConfig;
use crate::plugin::{PluginContext, PluginEngine};

/// Summary report of a completed build operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildReport {
    pub target: BuildTarget,
    pub release: bool,
    pub artifacts: Vec<PathBuf>,
}

/// Build runner engine.
pub struct BuildRunner;

impl BuildRunner {
    /// Builds application artifacts for the specified target.
    pub fn build(
        target: BuildTarget,
        release: bool,
        out_dir: &Path,
    ) -> Result<BuildReport, String> {
        Self::build_with_options(target, release, false, out_dir, None)
    }

    /// Builds application artifacts with an optional environment override.
    pub fn build_with_env(
        target: BuildTarget,
        release: bool,
        out_dir: &Path,
        env: Option<&str>,
    ) -> Result<BuildReport, String> {
        Self::build_with_options(target, release, false, out_dir, env)
    }

    /// Builds application artifacts with force override and environment options.
    pub fn build_with_options(
        target: BuildTarget,
        release: bool,
        force: bool,
        out_dir: &Path,
        env: Option<&str>,
    ) -> Result<BuildReport, String> {
        let _ = force;

        let dist_target = out_dir.join("dist").join(target.as_str());
        fs::create_dir_all(&dist_target)
            .map_err(|e| format!("Failed to create build output directory: {}", e))?;

        // 1. Load project configuration and run plugin transformations
        let mut strata_cfg = StrataConfig::load_from_dir(out_dir).unwrap_or_default();
        let mut ctx = PluginContext::new(target, release, out_dir, &dist_target);
        if let Some(e) = env {
            ctx.environment = e.to_string();
        }
        let _ = PluginEngine::run_config_transformations(&mut strata_cfg, &ctx);

        let mut artifacts = Vec::new();

        match target {
            BuildTarget::WebJs => {
                let config = WebBuildConfig {
                    mode: WebTargetMode::PureJsDom,
                    app_title: strata_cfg.window.title.clone(),
                    app_js_name: strata_cfg.web.app_js_name.clone(),
                    styles_css_name: strata_cfg.web.styles_css_name.clone(),
                    ..Default::default()
                };

                // Root component blueprint for standalone bundle
                let blueprint = NodeBlueprint::Element {
                    tag: Tag::Div,
                    classes: vec!["flex flex-col items-center justify-center h-screen".to_string()].into(),
                    attributes: vec![],
                    children: vec![NodeBlueprint::text(strata_cfg.app.name.clone())],
                };

                let bundle = WebTargetBuilder::build(&config, &blueprint);

                // 1. index.html
                let html_path = dist_target.join("index.html");
                fs::write(&html_path, bundle.html)
                    .map_err(|e| format!("Failed to write index.html: {}", e))?;
                artifacts.push(html_path);

                // 2. app.js
                let app_js_path = dist_target.join(&config.app_js_name);
                fs::write(&app_js_path, bundle.js)
                    .map_err(|e| format!("Failed to write app.js: {}", e))?;
                artifacts.push(app_js_path);

                // 3. runtime.js
                if let Some(runtime_js) = bundle.runtime_js {
                    let runtime_path = dist_target.join(&config.runtime_js_name);
                    fs::write(&runtime_path, runtime_js)
                        .map_err(|e| format!("Failed to write runtime.js: {}", e))?;
                    artifacts.push(runtime_path);
                }

                // 4. styles.css
                if let Some(css) = bundle.css {
                    let css_path = dist_target.join(&config.styles_css_name);
                    fs::write(&css_path, css)
                        .map_err(|e| format!("Failed to write styles.css: {}", e))?;
                    artifacts.push(css_path);
                }
            }
            BuildTarget::WebWasm => {
                let config = WebBuildConfig {
                    mode: WebTargetMode::WasmCanvas,
                    app_title: strata_cfg.window.title.clone(),
                    ..Default::default()
                };

                let blueprint = NodeBlueprint::empty();
                let bundle = WebTargetBuilder::build(&config, &blueprint);

                let html_path = dist_target.join("index.html");
                fs::write(&html_path, bundle.html)
                    .map_err(|e| format!("Failed to write index.html: {}", e))?;
                artifacts.push(html_path);

                if let Some(loader_js) = bundle.wasm_loader {
                    let loader_path = dist_target.join(&config.loader_js_name);
                    fs::write(&loader_path, loader_js)
                        .map_err(|e| format!("Failed to write loader.js: {}", e))?;
                    artifacts.push(loader_path);
                }
            }
            BuildTarget::Desktop
            | BuildTarget::MacOs
            | BuildTarget::Windows
            | BuildTarget::Linux
            | BuildTarget::Android
            | BuildTarget::Ios => {
                let binary_name = format!("{}{}", strata_cfg.app.name, target.binary_extension());
                let bin_path = dist_target.join(&binary_name);
                let target_triple = target.default_target_triple();

                let mut compiled_via_cargo = false;
                if out_dir.join("Cargo.toml").exists() {
                    let mut cmd = std::process::Command::new("cargo");
                    cmd.arg("build").arg("--target").arg(target_triple);
                    if release {
                        cmd.arg("--release");
                    }
                    cmd.current_dir(out_dir);
                    match cmd.output() {
                        Ok(output) if output.status.success() => {
                            let cargo_out = out_dir
                                .join("target")
                                .join(target_triple)
                                .join(if release { "release" } else { "debug" })
                                .join(&binary_name);
                            if cargo_out.exists() {
                                if let Ok(bytes) = fs::read(&cargo_out) {
                                    BinaryValidator::validate_target_architecture(target, &bytes)?;
                                    fs::write(&bin_path, &bytes).map_err(|e| e.to_string())?;
                                    compiled_via_cargo = true;
                                }
                            }
                        }
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let is_missing_target = stderr.contains("can't find crate for `std`")
                                || stderr.contains("target may not be installed")
                                || stderr.contains("was not found");
                            if is_missing_target {
                                return Err(format!(
                                    "Rust target '{}' is not installed.\n\
                                     To install this cross-compilation target, run:\n\
                                       rustup target add {}\n\
                                     Note: Platform-specific linkers (e.g. Android NDK, MinGW, or LLVM lld) may also be required.",
                                    target_triple, target_triple
                                ));
                            } else {
                                return Err(format!(
                                    "Cross-compilation for target '{}' ({}) failed:\n{}",
                                    target.as_str(),
                                    target_triple,
                                    stderr.trim()
                                ));
                            }
                        }
                        Err(e) => {
                            return Err(format!(
                                "Failed to invoke `cargo build --target {}`: {}",
                                target_triple, e
                            ));
                        }
                    }
                } else if bin_path.exists() {
                    if let Ok(bytes) = fs::read(&bin_path) {
                        if BinaryValidator::validate_target_architecture(target, &bytes).is_ok() {
                            compiled_via_cargo = true;
                        }
                    }
                }

                if !compiled_via_cargo {
                    return Err(format!(
                        "Cannot build binary for target '{}' ({}): No Cargo.toml found in '{}' and no pre-existing valid binary at '{}'.\n\
                         Please run this command within a valid Strata project directory with installed cross-compilation toolchains.",
                        target.as_str(),
                        target_triple,
                        out_dir.display(),
                        bin_path.display()
                    ));
                }
                artifacts.push(bin_path);

                let manifest_path = dist_target.join("strata_build.json");
                let manifest = format!(
                    r#"{{"app_name": "{}", "version": "{}", "target": "{}", "target_triple": "{}", "release": {}, "mode": "native_zero_chromium"}}"#,
                    strata_cfg.app.name,
                    strata_cfg.app.version,
                    target.as_str(),
                    target_triple,
                    release
                );
                fs::write(&manifest_path, manifest)
                    .map_err(|e| format!("Failed to write build manifest: {}", e))?;
                artifacts.push(manifest_path);
            }
        }

        Ok(BuildReport {
            target,
            release,
            artifacts,
        })
    }
}

/// Validates binary executable headers against expected target CPU architectures.
pub struct BinaryValidator;

impl BinaryValidator {
    pub fn validate_target_architecture(target: BuildTarget, bytes: &[u8]) -> Result<(), String> {
        if target == BuildTarget::WebJs {
            return Ok(());
        }
        if bytes.len() < 8 {
            return Err("Binary file is too small to contain valid executable headers".to_string());
        }

        match target {
            BuildTarget::Linux => {
                if bytes.len() < 20 || &bytes[0..4] != b"\x7fELF" {
                    return Err(format!("Expected Linux ELF binary, but got signature {:?}", &bytes[..4.min(bytes.len())]));
                }
                let machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap_or([0, 0]));
                if machine != 0x003E && machine != 0x00B7 {
                    return Err(format!("Invalid Linux ELF machine 0x{:04X}. Expected x86_64 (0x003E) or AArch64 (0x00B7)", machine));
                }
            }
            BuildTarget::Android => {
                if bytes.len() < 20 || &bytes[0..4] != b"\x7fELF" {
                    return Err(format!("Expected Android ELF shared object, but got signature {:?}", &bytes[..4.min(bytes.len())]));
                }
                let machine = u16::from_le_bytes(bytes[18..20].try_into().unwrap_or([0, 0]));
                if machine != 0x00B7 && machine != 0x0028 {
                    return Err(format!("Invalid Android ELF machine 0x{:04X}. Expected AArch64 (0x00B7) or ARM (0x0028), rejected host binary", machine));
                }
            }
            BuildTarget::Windows => {
                if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
                    return Err("Expected Windows PE binary with DOS 'MZ' header".to_string());
                }
                let pe_offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap_or([0, 0, 0, 0])) as usize;
                if bytes.len() < pe_offset + 6 {
                    return Err(format!("PE header out of bounds at offset {}", pe_offset));
                }
                if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
                    return Err("Missing 'PE\\0\\0' signature at e_lfanew".to_string());
                }
                let machine = u16::from_le_bytes(bytes[pe_offset + 4..pe_offset + 6].try_into().unwrap_or([0, 0]));
                if machine != 0x8664 && machine != 0xAA64 {
                    return Err(format!("Invalid Windows PE machine 0x{:04X}. Expected AMD64 (0x8664) or ARM64 (0xAA64)", machine));
                }
            }
            BuildTarget::MacOs => {
                let is_macho_64 = bytes[0..4] == [0xCF, 0xFA, 0xED, 0xFE] || bytes[0..4] == [0xFE, 0xED, 0xFA, 0xCF];
                let is_fat = bytes[0..4] == [0xCA, 0xFE, 0xBA, 0xBE] || bytes[0..4] == [0xBE, 0xBA, 0xFE, 0xCA];
                if !is_macho_64 && !is_fat {
                    return Err(format!("Expected macOS Mach-O binary, but got signature {:?}", &bytes[..4.min(bytes.len())]));
                }
            }
            BuildTarget::Ios => {
                let is_macho_64 = bytes[0..4] == [0xCF, 0xFA, 0xED, 0xFE] || bytes[0..4] == [0xFE, 0xED, 0xFA, 0xCF];
                if !is_macho_64 {
                    return Err(format!("Expected iOS Mach-O 64-bit binary, but got signature {:?}", &bytes[..4.min(bytes.len())]));
                }
                let cputype = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0, 0, 0, 0]));
                if cputype != 0x0100000C {
                    return Err(format!("Invalid iOS Mach-O cputype 0x{:08X}. Expected ARM64 (0x0100000C), rejected host binary", cputype));
                }
            }
            BuildTarget::WebWasm => {
                if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
                    return Err("Expected WebAssembly binary starting with \\0asm".to_string());
                }
            }
            BuildTarget::WebJs | BuildTarget::Desktop => {}
        }
        Ok(())
    }
}
