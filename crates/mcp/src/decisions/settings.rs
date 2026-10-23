//! How Decisions is set up on this machine: the provider, its model and
//! address, the day's cap, and the projects whose state is never sent —
//! `$XDG_CONFIG_HOME/devflow/decisions.json`. The key is apart, in the
//! credentials (`crate::credentials`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::deciding::Conf;

pub const FILE: &str = "decisions.json";
pub const OPENROUTER: &str = "https://openrouter.ai/api/v1";
pub const OPENROUTER_MODEL: &str = "typesafe/jev-1.13";
pub const DEFAULT_CAP_USD: f64 = 1.0;
/// Past this a cap is a typo, not a budget.
pub const MOST_CAP_USD: f64 = 1000.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "provider")]
    pub provider: String,
    /// Empty is the provider's default.
    #[serde(default)]
    pub model: String,
    /// Empty is the provider's address.
    #[serde(default)]
    pub url: String,
    #[serde(default = "cap")]
    pub daily_cap_usd: f64,
    /// Projects, by root, whose state is never sent.
    #[serde(default)]
    pub opted_out: Vec<String>,
}

fn provider() -> String {
    "openrouter".to_owned()
}

fn cap() -> f64 {
    DEFAULT_CAP_USD
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            provider: provider(),
            model: String::new(),
            url: String::new(),
            daily_cap_usd: DEFAULT_CAP_USD,
            opted_out: Vec::new(),
        }
    }
}

impl Settings {
    pub fn file() -> Option<PathBuf> {
        devflow_engine::home::config_dir().map(|config| config.join(FILE))
    }

    pub fn read_at(file: &Path) -> Settings {
        std::fs::read_to_string(file)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn of_user() -> Settings {
        Settings::file().map_or_else(Settings::default, |file| Settings::read_at(&file))
    }

    pub fn write_at(&self, file: &Path) -> Result<(), String> {
        self.checked()?;
        let folder = file.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(folder).map_err(|err| format!("{}: {err}", folder.display()))?;
        let text = serde_json::to_string_pretty(self).unwrap_or_default();
        let name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| FILE.to_owned());
        devflow_engine::fsguard::replace(folder, &name, format!("{text}\n").as_bytes())
            .map_err(|err| format!("{}: {err}", file.display()))
    }

    /// Refused when the provider, the address, the model or the cap is not one.
    pub fn checked(&self) -> Result<(), String> {
        if self.provider != "openrouter" {
            return Err("the provider is openrouter".to_owned());
        }
        if !reachable_address(&self.url) {
            return Err("the address is https, or a service on this machine".to_owned());
        }
        if self.model.len() > 200 || self.model.chars().any(char::is_whitespace) {
            return Err("that is not a model".to_owned());
        }
        if !self.daily_cap_usd.is_finite() || !(0.0..=MOST_CAP_USD).contains(&self.daily_cap_usd) {
            return Err(format!(
                "the daily cap is between 0 and {MOST_CAP_USD} dollars"
            ));
        }
        Ok(())
    }

    pub fn base(&self) -> String {
        if self.url.is_empty() {
            OPENROUTER.to_owned()
        } else {
            self.url.trim_end_matches('/').to_owned()
        }
    }

    pub fn model(&self) -> String {
        if self.model.is_empty() {
            OPENROUTER_MODEL.to_owned()
        } else {
            self.model.clone()
        }
    }

    /// What a decision needs, with the key from the credentials.
    pub fn conf(&self, key: Option<String>) -> Conf {
        Conf {
            base: self.base(),
            model: self.model(),
            cap_usd: self.daily_cap_usd,
            key,
            opted_out: self.opted_out.clone(),
            secrets: Vec::new(),
        }
    }
}

/// An address a key may be sent to: https, or this machine.
pub fn reachable_address(url: &str) -> bool {
    url.is_empty()
        || url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
