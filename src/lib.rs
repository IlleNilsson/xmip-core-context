#![forbid(unsafe_code)]

//! Message Context: what accumulates as a Message is handled.
//!
//! Content is immutable and context accumulates. Promoted properties land here
//! as text, and so does the identity a Message arrived with — both layers of
//! it, per ADR-0019 clause 6.
//!
//! [`property`] holds every name a property travels under when one layer
//! writes it and another reads it — a transport and the identity gates,
//! the runtime and a route (ADR-0019, amendment 2026-09-24).
//! [`facts_record`] is the identity facts' one binary form, what the Ledger
//! keeps beside a held Journey.

pub mod facts;
pub mod facts_record;
pub mod property;

pub use facts::{
    Alignment, AlignmentResult, AuthenticatedIdentity, IdentityFacts, OnMisalignment, Verified,
};

use std::collections::BTreeMap;

use xcore::ScalarValue;

/// What a Message's handling accumulates. A promoted property's value is one
/// scalar, `xcore::ScalarValue`, so a promoted property and a structured
/// content field are the same type, not two identical ones.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MessageContext {
    values: BTreeMap<String, ScalarValue>,
}

impl MessageContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&ScalarValue> {
        self.values.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn with_value(mut self, key: impl Into<String>, value: ScalarValue) -> Self {
        self.values.insert(key.into(), value);
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &ScalarValue)> {
        self.values.iter().map(|(key, value)| (key.as_str(), value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_built_immutably() {
        let context = MessageContext::new()
            .with_value("source.uri", ScalarValue::Text("file:///in/a.xml".into()));
        assert!(context.contains_key("source.uri"));
    }
}
