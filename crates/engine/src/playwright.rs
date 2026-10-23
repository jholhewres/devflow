//! The Playwright config a setup writes when Playwright is the project's E2E
//! tool: Devflow's specs from `e2e_dir`, a JUnit report in
//! `$DEVFLOW_REPORT_DIR`, and every screenshot and video kept as the run's
//! evidence. The project's own config, when it has one, is the base — its
//! server, its address, its browsers — and its own tests stay where they are.

use crate::config::Config;
use crate::detect::Detected;

/// Where it is written, relative to the project's root.
pub const FILE: &str = ".devpit/devflow/playwright.config.ts";

/// The tool's name, as detection reports it.
pub const TOOL: &str = "playwright";

/// The command an `e2e` check runs Devflow's specs with, through the
/// project's own runner (`npx`, `pnpm exec`, …).
pub fn command(exec: &str) -> String {
    format!("{exec} playwright test --config {FILE}")
}

/// Whether the setup writes the config: Playwright was detected in the
/// project, or a check the person chose runs it.
pub fn wanted(config: &Config, detected: &Detected) -> bool {
    detected.e2e_tools.iter().any(|tool| tool.name == TOOL)
        || config
            .stages
            .execution
            .checks
            .iter()
            .any(|check| check.run.contains(TOOL))
}

/// The project's own config, as detection found it, to start from.
pub fn base(detected: &Detected) -> Option<&str> {
    detected
        .e2e_tools
        .iter()
        .find(|tool| tool.name == TOOL)
        .map(|tool| tool.source.as_str())
        .filter(|source| source.starts_with("playwright.config."))
}

/// The config's text, for specs in `e2e_dir` and, when given, on top of the
/// project's `base` config at its root.
pub fn text(e2e_dir: &str, base: Option<&str>) -> String {
    // An import names a TypeScript or JavaScript module without its extension.
    let import = base.map(|file| {
        let module = file
            .strip_suffix(".ts")
            .or_else(|| file.strip_suffix(".js"))
            .unwrap_or(file);
        format!("import base from '../../{module}'\n")
    });
    let (spread, use_base, server) = match &import {
        Some(_) => (
            "  ...base,\n",
            "...base.use, ",
            "  // The project's server starts from its root, not from this folder.\n  \
             ...(base.webServer\n    \
             ? { webServer: [base.webServer].flat().map((server) => ({ cwd: root, ...server })) }\n    \
             : {}),\n",
        ),
        None => (
            "",
            "",
            "  // Where the app under test is: set use.baseURL, or a webServer that starts it.\n",
        ),
    };
    format!(
        "// Devflow's Playwright config, written by devpit's setup: the specs Devflow\n\
         // writes in {e2e_dir}, with a JUnit report and every screenshot and video\n\
         // kept in $DEVFLOW_REPORT_DIR as the run's evidence. It is yours to change:\n\
         // a setup run again keeps your copy. Run it from the project's root.\n\
         import {{ defineConfig }} from '@playwright/test'\n\
         {import}\n\
         const root = process.cwd()\n\
         const reports = process.env.DEVFLOW_REPORT_DIR ?? `${{root}}/.devpit/devflow/runs/local`\n\
         \n\
         export default defineConfig({{\n\
         {spread}  testDir: `${{root}}/{e2e_dir}`,\n  \
         testMatch: '**/*.spec.ts',\n  \
         outputDir: `${{reports}}/test-results`,\n  \
         reporter: [['list'], ['junit', {{ outputFile: `${{reports}}/report.xml` }}]],\n  \
         use: {{ {use_base}screenshot: 'on', video: 'on' }},\n\
         {server}}})\n",
        import = import.unwrap_or_default(),
    )
}

#[cfg(test)]
#[path = "playwright_tests.rs"]
mod tests;
