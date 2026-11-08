# Strata CLI

Universal developer CLI, scaffolding engine, and cross-platform native packaging toolchain for Strata applications.

## Overview

Strata CLI (`strata`) provides the developer toolchain for initializing, developing, building, testing, and distributing Strata applications across all supported target platforms: native desktop (Linux, macOS, Windows), mobile (Android, iOS), WebAssembly, and terminal (TUI).

## Key Features

- **Project Scaffolding (`strata init` / `strata new`):** Generates full project structures with preconfigured RSX component trees, Tailwind emulation, and target platform manifests.
- **Interactive Setup Wizard (`strata init --interactive`):** Guides developers through target platform selection, state management choices, and CI workflow configurations.
- **Cross-Platform Packager (`strata package`):** Generates production application bundles:
  - Linux: Standalone AppImage bundles and Debian packages (`.deb`).
  - macOS: Application bundles (`.app`) and disk images (`.dmg`).
  - Windows: Portable executables and MSI installer packages.
  - WebAssembly: Optimized WASM binaries with companion HTML/JS loaders.
- **Live Development Server (`strata dev`):** Local WebSocket development bridge coordinating hot reloading, UI state snapshotting, and telemetry introspection.
- **Multi-Target Compilation (`strata build`):** High-level wrapper over `cargo build` orchestrating feature flags and cross-compilation target triplets.

## Verification & Testing

```bash
cargo check --all-targets
cargo test
```

## License

Licensed under the MIT License. See [LICENSE](file:///home/usr/Projects/strataui/cli/LICENSE) for details.
