mod assets;
mod catalog;
mod compatibility;
mod eval;
mod lifecycle;
mod secure_fs;
mod snapshot;
mod verifier;

pub use assets::{GeneratedAssets, ROUTING_END, ROUTING_START, generate_assets};
pub use catalog::{Catalog, CatalogError};
pub use compatibility::{CompatibilityReport, check_compatibility};
pub use eval::{CertificationCounts, CertificationReport, score_certification, wilson_interval};
pub use lifecycle::{
    CommandError, DoctorReport, LifecycleCommand, LifecycleOptions, RecoveryStrategy, Roots,
    execute_lifecycle,
};
pub use snapshot::{GitDiffMetadata, Snapshot, SnapshotEntry, create_snapshot};
pub use verifier::{EvidencePacket, VerifyRequest, verifier_login, verify};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
