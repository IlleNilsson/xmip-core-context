//! Both identities a Message arrived with, and how they relate.
//!
//! ADR-0019 clause 6: where both exist, both are recorded and neither is
//! discarded. Five facts per identity — the value, the evidence that
//! authenticated it, the layer it came from, the Party it resolved to, and the
//! alignment result across the pair.
//!
//! Collapsing them into one `identity` field loses the distinction exactly when
//! it is needed, because a dispute about who sent what is a question about
//! both.

use std::fmt;
use xmip_core::PartyId;
use xmip_core::{Established, IdentityClass, Layer, Mechanism};

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
    /// A name was claimed and the mechanism carries nothing to prove it. X12's
    /// ISA06, EDIFACT's UNB, HL7's MSH-3. What the protocol provides.
    Claimed,
    /// The mechanism could have proved the claim and did not.
    Refused,
}

/// One identity, on one layer, and everything known about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIdentity {
    /// How it was proven, or would have been.
    pub mechanism: Mechanism,
    /// The value presented — `CN=partner-x.example`, `ISA06=PARTNERX`.
    pub value: String,
    /// How the first gate came by it: passed, inferred or detected.
    ///
    /// Survives to here because it is what an operator asks for when a Journey
    /// is disputed. "Proven" answers whether the claim held; this answers why
    /// there was a claim at all, and a record with only the first cannot tell a
    /// forged certificate from a folder anyone could write to.
    pub established: Established,
    /// What the gate concluded.
    pub verified: Verified,
    /// The Party it resolved to, where the registry knew one.
    ///
    /// `None` is ordinary: an unrecognised caller is still authenticated or
    /// refused on its own terms. A Party is a shortcut to an identity, not a
    /// permission, so failing to resolve one decides nothing by itself.
    pub party_id: Option<PartyId>,
    /// Free-form detail the gate wants on the record — issuer, thumbprint,
    /// token id, source address. Audit reads this; nothing branches on it.
    pub evidence: Vec<(String, String)>,

    /// When the gate concluded, in unix nanoseconds. Zero means unrecorded.
    ///
    /// **A Journey may take days.** A Process waits for a human, and by the
    /// time it resumes the certificate may have expired, the token lapsed, the
    /// Party been revoked. What is recorded here is what was true *then*, and
    /// it is never a licence to act *now* — which is exactly why the time has
    /// to travel with it.
    ///
    /// Zero is treated as never proven by anything that judges freshness. An
    /// identity that cannot say when it was verified is not fresh.
    pub authenticated_at: i128,
}

impl AuthenticatedIdentity {
    #[must_use]
    pub fn new(
        mechanism: Mechanism,
        value: impl Into<String>,
        established: Established,
        verified: Verified,
    ) -> Self {
        Self {
            mechanism,
            value: value.into(),
            established,
            verified,
            party_id: None,
            evidence: Vec::new(),
            authenticated_at: 0,
        }
    }

    /// Record when the gate concluded. `Clock::unix_timestamp_nanos`.
    #[must_use]
    pub const fn at(mut self, unix_nanos: i128) -> Self {
        self.authenticated_at = unix_nanos;
        self
    }

    /// How long ago this was proven, or `None` if it never said.
    ///
    /// `None` and "a long time ago" are different answers and a caller has to
    /// be able to tell them apart — one is a gap in the record, the other is a
    /// stale credential.
    #[must_use]
    pub const fn age_at(&self, now: i128) -> Option<i128> {
        if self.authenticated_at == 0 {
            return None;
        }

        Some(now - self.authenticated_at)
    }

    #[must_use]
    pub const fn resolving_to(mut self, party_id: PartyId) -> Self {
        self.party_id = Some(party_id);
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn layer(&self) -> Layer {
        self.mechanism.layer()
    }

    #[must_use]
    pub fn class(&self) -> IdentityClass {
        self.mechanism.class()
    }
}

/// How much agreement configuration requires. ADR-0019 clause 7.
///
/// This is DMARC's structure, adopted deliberately: SPF proves the envelope
/// sender, DKIM proves the author domain, and DMARC is neither — it is the
/// alignment policy between them plus what to do when alignment fails. The same
/// problem, a decade in production on internet mail, standardised as RFC 9989.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Alignment {
    /// Record both, never compare. The relaying case, and the default.
    ///
    /// A default of `Strict` would refuse every relayed integration on the
    /// first day, and the failure would present as a routing bug rather than a
    /// policy decision — which is precisely how this goes wrong in products
    /// that ship the other default.
    #[default]
    None,
    /// The same Party through a different endpoint, matched at the Party rather
    /// than at the credential.
    Relaxed,
    /// Transport credential and message identity must resolve to the same
    /// Party.
    Strict,
}

/// What to do when alignment fails.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OnMisalignment {
    /// Proceed. The misalignment is recorded here and audited.
    #[default]
    Accept,
    /// To the Xmip DMQ with both identities and the alignment result, per
    /// ADR-0013.
    Quarantine,
    /// Refused at message authorization.
    Reject,
}

/// The outcome of comparing the two layers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlignmentResult {
    /// Policy is `None`. Both are on the record and neither was compared.
    NotCompared,
    /// Nothing to compare against. ADR-0019's first degenerate case: the
    /// transport identity is authoritative for both questions and alignment is
    /// vacuously satisfied. This is most of the estate.
    NoMessageIdentity,
    Aligned,
    /// **Not an error.** It is the normal case for a relaying VAN, a service
    /// bus, an API gateway and a managed file transfer broker — every
    /// arrangement where one authenticated connection carries traffic for many
    /// Parties. A platform that treats this as a fault cannot integrate with
    /// any of them.
    Misaligned,
}

impl AlignmentResult {
    #[must_use]
    pub const fn is_misaligned(self) -> bool {
        matches!(self, Self::Misaligned)
    }
}

/// Both identities a Message arrived with, and the alignment across them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityFacts {
    /// Always present. Transport security always has *something* to verify,
    /// even when that something is a circumstance — which is why the mandatory
    /// pass is transport and the optional pass is message, rather than one
    /// configurable pass over whichever happens to be there.
    pub transport: AuthenticatedIdentity,
    /// Present where the representation carries one. Message security often
    /// has nothing: a raw CSV carries no message identity at all.
    pub message: Option<AuthenticatedIdentity>,
    pub alignment: AlignmentResult,
}

impl IdentityFacts {
    /// Record both and evaluate the policy across them.
    #[must_use]
    pub fn evaluate(
        policy: Alignment,
        transport: AuthenticatedIdentity,
        message: Option<AuthenticatedIdentity>,
    ) -> Self {
        let alignment = match (policy, message.as_ref()) {
            (Alignment::None, _) => AlignmentResult::NotCompared,
            (_, None) => AlignmentResult::NoMessageIdentity,

            // Relaxed and Strict both compare at the Party today, and that is
            // not an oversight — ADR-0019 expresses alignment at the Party
            // rather than at the credential precisely so a partner reaching
            // Xmip through two endpoints with two certificates is still one
            // Party.
            //
            // What will separate them is Party hierarchy, which ADR-0007 makes
            // recursive and ADR-0019 leaves open: whether a fleet certificate
            // aligns with a ship's own identifier. That is DMARC's
            // organizational-domain widening, and `Relaxed` is where it lands
            // when the question is answered. Until then the two behave alike,
            // stated here rather than discovered.
            (Alignment::Relaxed | Alignment::Strict, Some(message)) => {
                match (transport.party_id, message.party_id) {
                    (Some(from_transport), Some(from_message)) if from_transport == from_message => {
                        AlignmentResult::Aligned
                    }
                    // One side resolved to nothing. There is no Party to agree
                    // on, so the policy is not satisfied.
                    _ => AlignmentResult::Misaligned,
                }
            }
        };

        Self {
            transport,
            message,
            alignment,
        }
    }

    /// Who the Journey is **for** — Subscription matching, Party resolution,
    /// contract selection, billing. ADR-0019 clause 7.
    ///
    /// The message identity where one exists, because that is what names the
    /// counterparty the work belongs to. Falls back to transport, which is the
    /// first degenerate case: with no message identity the transport is
    /// authoritative for both questions.
    #[must_use]
    pub fn subject(&self) -> &AuthenticatedIdentity {
        self.message.as_ref().unwrap_or(&self.transport)
    }

    /// Who is **accountable for the transmission** — audit, rate limiting,
    /// credential revocation, non-repudiation of delivery.
    ///
    /// Always the transport identity. "Which identity wins" is the wrong
    /// question; they answer different ones.
    #[must_use]
    pub const fn accountable(&self) -> &AuthenticatedIdentity {
        &self.transport
    }
}

impl fmt::Display for IdentityFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transport {}={}",
            self.transport.mechanism.name(),
            self.transport.value
        )?;

        if let Some(message) = &self.message {
            write!(f, " message {}={}", message.mechanism.name(), message.value)?;
        }

        write!(f, " alignment {:?}", self.alignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmip_core::mechanism;

    fn tls(party: Option<PartyId>) -> AuthenticatedIdentity {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=van.example",
            Established::Passed,
            Verified::Proven,
        );

        match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        }
    }

    fn isa06(party: Option<PartyId>) -> AuthenticatedIdentity {
        let identity = AuthenticatedIdentity::new(
            mechanism::edi_x12_interchange(),
            "ISA06=PARTNERX",
            Established::Detected,
            Verified::Claimed,
        );

        match party {
            Some(party_id) => identity.resolving_to(party_id),
            None => identity,
        }
    }

    #[test]
    fn the_default_never_compares() {
        // A relaying VAN carries traffic for many Parties over one connection.
        // Under the default that is ordinary, not a fault.
        let facts = IdentityFacts::evaluate(
            Alignment::default(),
            tls(Some(PartyId::new(1))),
            Some(isa06(Some(PartyId::new(2)))),
        );

        assert_eq!(facts.alignment, AlignmentResult::NotCompared);
        assert!(!facts.alignment.is_misaligned());
    }

    #[test]
    fn strict_requires_one_party_across_both_layers() {
        let same = IdentityFacts::evaluate(
            Alignment::Strict,
            tls(Some(PartyId::new(1))),
            Some(isa06(Some(PartyId::new(1)))),
        );
        let different = IdentityFacts::evaluate(
            Alignment::Strict,
            tls(Some(PartyId::new(1))),
            Some(isa06(Some(PartyId::new(2)))),
        );

        assert_eq!(same.alignment, AlignmentResult::Aligned);
        assert_eq!(different.alignment, AlignmentResult::Misaligned);
    }

    #[test]
    fn no_message_identity_satisfies_alignment_vacuously() {
        // Most of the estate. A raw CSV carries no message identity at all.
        let facts = IdentityFacts::evaluate(Alignment::Strict, tls(Some(PartyId::new(1))), None);

        assert_eq!(facts.alignment, AlignmentResult::NoMessageIdentity);
        assert_eq!(facts.subject(), facts.accountable());
    }

    #[test]
    fn the_two_layers_answer_different_questions() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            tls(Some(PartyId::new(1))),
            Some(isa06(Some(PartyId::new(2)))),
        );

        // Who the Journey is for, and who is accountable for the transmission.
        assert_eq!(facts.subject().party_id, Some(PartyId::new(2)));
        assert_eq!(facts.accountable().party_id, Some(PartyId::new(1)));
    }

    #[test]
    fn a_claimed_identity_is_recorded_as_claimed_not_as_proven() {
        let facts = IdentityFacts::evaluate(Alignment::None, tls(None), Some(isa06(None)));

        assert_eq!(facts.transport.verified, Verified::Proven);
        assert_eq!(facts.message.as_ref().unwrap().verified, Verified::Claimed);
    }

    #[test]
    fn an_unresolved_party_cannot_align() {
        // Nothing to agree on. The policy asked for one Party across both
        // layers and one layer named nobody.
        let facts =
            IdentityFacts::evaluate(Alignment::Strict, tls(Some(PartyId::new(1))), Some(isa06(None)));

        assert_eq!(facts.alignment, AlignmentResult::Misaligned);
    }

    #[test]
    fn anonymous_still_produces_a_transport_identity() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::anonymous(),
                "",
                Established::Inferred,
                Verified::Proven,
            ),
            None,
        );

        assert_eq!(facts.transport.class(), IdentityClass::Anonymous);
        assert_eq!(facts.transport.verified, Verified::Proven);
    }

    #[test]
    fn evidence_is_kept_for_audit_and_nothing_branches_on_it() {
        let facts = IdentityFacts::evaluate(
            Alignment::None,
            tls(Some(PartyId::new(1)))
                .with_evidence("issuer", "CN=Example CA")
                .with_evidence("thumbprint", "AB:CD"),
            None,
        );

        assert_eq!(facts.transport.evidence.len(), 2);
    }
}
