#![forbid(unsafe_code)]

//! Message Context: what accumulates as a Message is handled.
//!
//! Content is immutable and context accumulates. Promoted properties land here
//! as text, and so does the identity a Message arrived with — both layers of
//! it, per ADR-0019 clause 6.

pub mod identity;

pub use identity::{
    Alignment, AlignmentResult, AuthenticatedIdentity, IdentityFacts, OnMisalignment, Verified,
};

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum ContextValue {
    Null,
    Bool(bool),
    Integer(i64),
    Decimal(f64),
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MessageContext {
    values: BTreeMap<String, ContextValue>,
}

impl MessageContext {
    pub fn new() -> Self { Self::default() }

    pub fn get(&self, key: &str) -> Option<&ContextValue> {
        self.values.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    pub fn with_value(mut self, key: impl Into<String>, value: ContextValue) -> Self {
        self.values.insert(key.into(), value);
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &ContextValue)> {
        self.values.iter().map(|(key, value)| (key.as_str(), value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_built_immutably() {
        let context = MessageContext::new().with_value("source.uri", ContextValue::Text("file:///in/a.xml".into()));
        assert!(context.contains_key("source.uri"));
    }
}
