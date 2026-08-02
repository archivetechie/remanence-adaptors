//! Adapter-enabled Remanence distribution assembly.
//!
//! This crate contains no parser logic. It selects auxiliary adapters at
//! compile time, registers them with the core contract, and exposes the same
//! CLI and daemon entrypoints as Remanence.

use std::sync::Arc;

use remanence_bru::BruFormat;
use remanence_format_driver::{ForeignFormatRegistry, FormatRegistryError};

/// Build the exact foreign-format registry linked into this distribution.
pub fn registry() -> Result<ForeignFormatRegistry, FormatRegistryError> {
    let mut registry = ForeignFormatRegistry::new();
    registry.register(Arc::new(BruFormat))?;
    Ok(registry)
}
