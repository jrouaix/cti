#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod attack_pattern;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod bundle;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod campaign;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod confidence;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod course_of_action;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod error;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod grouping;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod id;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod identity;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod indicator;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod infrastructure;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod intrusion_set;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod location;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod malware;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod malware_analysis;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod marking_definition;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod note;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod object;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod observed_data;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod opinion;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod reference;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod relationship;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod relationship_graph;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod report;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod sighting;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod standard;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod threat_actor;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod tool;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
pub mod vocab;
#[allow(clippy::all, clippy::pedantic, clippy::restriction, clippy::nursery)]
mod vulnerability;

pub use attack_pattern::AttackPattern;
pub use bundle::Bundle;
pub use campaign::Campaign;
pub use confidence::Confidence;
pub use course_of_action::CourseOfAction;
pub use error::IdTypeMismatchError;
pub use grouping::Grouping;
pub use id::{Id, IdParseError};
#[doc(inline)]
pub use identity::Identity;
pub use indicator::Indicator;
pub use infrastructure::Infrastructure;
pub use intrusion_set::IntrusionSet;
pub use location::Location;
pub use malware::Malware;
pub use malware_analysis::MalwareAnalysis;
pub use marking_definition::MarkingDefinition;
pub use note::Note;
pub use object::{CommonProperties, Object, TypedObject};
pub use observed_data::ObservedData;
pub use opinion::Opinion;
pub use reference::{ExternalReference, KillChainPhase};
pub use relationship::{Relationship, RelationshipType};
pub use relationship_graph::RelationshipGraph;
pub use report::Report;
pub use sighting::Sighting;
pub use threat_actor::ThreatActor;
pub use tool::Tool;
pub use vulnerability::Vulnerability;

pub use stix_derive::*;

#[doc(hidden)]
pub mod export {
    pub use indexmap::IndexMap;
    pub use once_self_cell::sync_once_self_cell;
    pub mod petgraph {
        pub use ::petgraph::{graph::NodeIndex, Graph};
    }
}

/// Trait for turning a reference in a STIX collection into a data-carrying node.
pub trait Resolve {
    /// The node type, containing a reference to the data and the backing collection.
    type Output;

    /// Produce a collection-attached node for the object identified by the ID.
    fn resolve(self) -> Option<Self::Output>;
}
