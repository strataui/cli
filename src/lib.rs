//! Strata CLI: Developer Toolchain, Project Scaffolding, HMR Dev Engine, Multi-Target Builder, and Packager.

pub mod args;
pub mod builder;
pub mod config;
pub mod dev_server;
pub mod packager;
pub mod parity;
pub mod plugin;
pub mod prompt;
pub mod scaffold;
pub mod wizard;

pub use args::{BuildTarget, CliArgs, CliCommand, PackageFormat, TemplateKind};
pub use builder::{BinaryValidator, BuildReport, BuildRunner};
pub use config::{AppConfig, EnvironmentConfig, PluginSpec, SigningConfig, StrataConfig, WebConfigSection, WindowConfigSection};
pub use dev_server::{CargoHmrOrchestrator, DevServer, DevServerConfig, HmrPatchReport, HmrSession};
pub use packager::{CodeSigner, PackageOptions, PackageReport, Packager, SigningReport};
pub use parity::{ParityHarness, ParityReport, ParityTestCase};
pub use plugin::{PluginContext, PluginEngine, StrataBuildPlugin};
pub use prompt::{
    ConfirmPrompt, Key, MultiSelectItem, MultiSelectModal, MultiSelectPrompt, OptionModal,
    PromptTheme, RawModeGuard, SelectItem, SelectPrompt, Terminal, TextPrompt,
};
pub use scaffold::{ProjectScaffolder, ScaffoldReport};
pub use wizard::{ProjectWizard, WizardConfig};

/// CLI Toolchain prelude.
pub mod prelude {
    pub use super::args::{BuildTarget, CliArgs, CliCommand, PackageFormat, TemplateKind};
    pub use super::builder::{BinaryValidator, BuildReport, BuildRunner};
    pub use super::config::{AppConfig, EnvironmentConfig, PluginSpec, SigningConfig, StrataConfig, WebConfigSection, WindowConfigSection};
    pub use super::dev_server::{CargoHmrOrchestrator, DevServer, DevServerConfig, HmrPatchReport, HmrSession};
    pub use super::packager::{CodeSigner, PackageOptions, PackageReport, Packager, SigningReport};
    pub use super::parity::{ParityHarness, ParityReport, ParityTestCase};
    pub use super::plugin::{PluginContext, PluginEngine, StrataBuildPlugin};
    pub use super::prompt::{
        ConfirmPrompt, Key, MultiSelectItem, MultiSelectModal, MultiSelectPrompt, OptionModal,
        PromptTheme, RawModeGuard, SelectItem, SelectPrompt, Terminal, TextPrompt,
    };
    pub use super::scaffold::{ProjectScaffolder, ScaffoldReport};
    pub use super::wizard::{ProjectWizard, WizardConfig};
}
