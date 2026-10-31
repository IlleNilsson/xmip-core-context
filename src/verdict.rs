//! What a gate concluded about one presented identity, and the weakest
//! conclusion a Receive Location takes (ADR-0019, amendment 2026-10-31).

/// What a gate concluded about one presented identity.
///
/// Every arrival gets one of these, on the transport layer at minimum. ADR-0019
/// clause 2: anonymous is an authenticated outcome and not a skipped gate — the
/// claim is "nobody", it is verified as such, and authorization decides
/// afterwards whether nobody may post here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verified {
    /// The mechanism proved the claim.
    Proven,
    /// A third party Xmip proved checked the claim and says so: a broker
    /// that matched a message's user id against the connection it
    /// authenticated. As strong as Xmip's own proof of that party, and never
    /// called proven (ADR-0019, amendment 2026-10-31).
    Vouched,
    /// A name was claimed and the mechanism carries nothing to prove it. X12's
    /// ISA06, EDIFACT's UNB, HL7's MSH-3. What the protocol provides.
    Claimed,
    /// The mechanism could have proved the claim and did not.
    Refused,
}

impl Verified {
    /// Every conclusion, the strongest first.
    pub const ALL: [Self; 4] = [Self::Proven, Self::Vouched, Self::Claimed, Self::Refused];

    /// The word it is written in, here and nowhere else.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Vouched => "vouched",
            Self::Claimed => "claimed",
            Self::Refused => "refused",
        }
    }

    /// Whether this verdict is at least as strong as `minimum`. A refused
    /// claim meets none.
    #[must_use]
    pub const fn meets(self, minimum: Required) -> bool {
        self.strength() >= minimum.verdict().strength()
    }

    const fn strength(self) -> u8 {
        match self {
            Self::Proven => 3,
            Self::Vouched => 2,
            Self::Claimed => 1,
            Self::Refused => 0,
        }
    }

    /// The conclusion a word names, exactly: what a record kept of it read
    /// back.
    #[must_use]
    pub fn named(word: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|verified| verified.word() == word)
    }

    /// Whether the mechanism proved the claim: the one answer to "proven"
    /// anything records, read from the verdict and never from the
    /// mechanism's name or the assurance its catalog states.
    #[must_use]
    pub const fn is_proven(self) -> bool {
        matches!(self, Self::Proven)
    }
}

/// The weakest verdict a Receive Location takes on one layer: `proven`
/// unless the Location writes a weaker one, so a claim nothing proved is
/// taken only where configuration says so.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Required {
    #[default]
    Proven,
    Vouched,
    Claimed,
}

impl Required {
    /// The verdict it names.
    #[must_use]
    pub const fn verdict(self) -> Verified {
        match self {
            Self::Proven => Verified::Proven,
            Self::Vouched => Verified::Vouched,
            Self::Claimed => Verified::Claimed,
        }
    }

    /// Whether it is the default, `proven`: what a configuration leaves
    /// unwritten.
    #[must_use]
    pub const fn is_proven(&self) -> bool {
        matches!(self, Self::Proven)
    }
}

/// The weakest verdict a Location takes on each layer, checked before any
/// policy is asked (`authorize::authorize`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Minimum {
    pub transport: Required,
    pub message: Required,
}

impl Minimum {
    /// Whatever the gates concluded short of refused: for a point that
    /// authorizes again what a Receive Location already took at its own
    /// minimum.
    pub const TAKEN: Self = Self {
        transport: Required::Claimed,
        message: Required::Claimed,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_meets_its_minimum_and_none_stronger_and_refused_meets_none() {
        assert!(!Verified::Vouched.meets(Required::Proven));
        assert!(!Verified::Claimed.meets(Required::Vouched));
        assert!(Verified::Proven.meets(Required::Claimed));
        for required in [Required::Proven, Required::Vouched, Required::Claimed] {
            assert!(!Verified::Refused.meets(required), "{required:?}");
            assert!(required.verdict().meets(required));
        }
        assert_eq!(Minimum::default().transport, Required::Proven);
        assert_eq!(Minimum::default().message, Required::Proven);
    }

    #[test]
    fn a_conclusion_is_its_word() {
        for verified in Verified::ALL {
            assert_eq!(Verified::named(verified.word()), Some(verified));
        }
        assert_eq!(Verified::named("Proven"), None);
    }
}
