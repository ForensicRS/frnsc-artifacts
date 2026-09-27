//! The [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) definitions as static
//! Rust data: where on a host each artifact lives.
//!
//! [`CATALOG`] holds every definition of the upstream commit [`KB_COMMIT`], generated into
//! `src/generated/` by `tools/gen_catalog.py`. Nothing is read at run time. Hand it to a pipeline
//! so parsers can resolve the definitions they declare:
//!
//! ```
//! use forensic_rs::prelude::*;
//!
//! let sources = TriageSources::builder().catalog(frnsc_artifacts::catalog()).build();
//! # let _ = sources;
//! let amcache = frnsc_artifacts::CATALOG.get("WindowsAMCacheHveFile").unwrap();
//! assert!(amcache.supports(Os::Windows));
//! ```
//!
//! Parsers never depend on this crate: they name the definitions they consume with
//! `Requirement::artifact(..)` from `forensic-rs`, and the pipeline supplies the catalog.
//! [`output_artifact`] maps a definition to the [`Artifact`](forensic_rs::artifact::Artifact)
//! a parser reports for it, where that is known.

use std::sync::Arc;

use forensic_rs::catalog::{ArtifactCatalog, SliceCatalog};

#[rustfmt::skip]
mod generated;
mod mapping;

pub use generated::{DEFINITION_COUNT, KB_COMMIT, KB_REPO};
pub use mapping::{output_artifact, MAPPED_DEFINITIONS};

/// Every ForensicArtifacts definition of [`KB_COMMIT`], looked up by name or alias.
pub static CATALOG: SliceCatalog =
    SliceCatalog::from_static(&generated::DEFINITIONS, &generated::INDEX);

/// [`CATALOG`] as the trait object `TriageSourcesBuilder::catalog` takes. Cheap: the clone
/// borrows the static data.
pub fn catalog() -> Arc<dyn ArtifactCatalog> {
    Arc::new(CATALOG.clone())
}
