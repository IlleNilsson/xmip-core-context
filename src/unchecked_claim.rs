//! A claim an arrival presented that no authenticator checked.
//!
//! The owner, 2026-10-29: *First you present your identity, then you get
//! identified. Then we look to authentication, do your identification hold
//! up.* An arrival may present more than one claim — a certificate's
//! subject and a Basic user name on one request — and the gate
//! authenticates one per layer. Every other one is kept here: on the record
//! as what was claimed, its proof left behind, and never handed to
//! authorization (ADR-0019, amendment 2026-10-30).

use xcore::{Established, Mechanism};

use crate::Verified;

/// One claim no authenticator checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UncheckedClaim {
    /// The mechanism the claim was presented under.
    pub mechanism: Mechanism,
    /// The value claimed — `jane`, `CN=party-x.example`.
    pub value: String,
    /// How the first gate came by it: passed, inferred or detected.
    pub established: Established,
}

impl UncheckedClaim {
    #[must_use]
    pub fn new(mechanism: Mechanism, value: impl Into<String>, established: Established) -> Self {
        Self {
            mechanism,
            value: value.into(),
            established,
        }
    }

    /// What it is recorded as: claimed, because nothing checked it.
    #[must_use]
    pub const fn verified(&self) -> Verified {
        Verified::Claimed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::mechanism;

    #[test]
    fn an_unchecked_claim_is_claimed_and_never_proven() {
        let claim = UncheckedClaim::new(mechanism::username(), "jane", Established::Passed);
        assert_eq!(claim.verified(), Verified::Claimed);
        assert!(!claim.verified().is_proven());
    }
}
