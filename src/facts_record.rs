//! What arrival concluded of a Message's identities, in one binary form:
//! what the Ledger keeps beside a Message a paused Subscription holds, so
//! its departure reads back the identities the Message arrived with,
//! whichever node picks it up and however long after (ADR-0019 clause 6;
//! `runtime-model.md` section 9).
//!
//! The fields are written in their order — no names, no padding, as the
//! Message's and the Journey's records are: text as its length and its
//! UTF-8 bytes, an identifier as 16 bytes big-endian, a time as 16, each
//! enumeration as its number, an absent value as one byte saying so. The
//! first byte is the form's number, [`FORM`].
//!
//! **A mechanism is never built from a record** (`xcore::Mechanism`): the
//! record names it, and [`IdentityFacts::from_record`] is told which
//! mechanism of that name the reader carries. One the reader no longer
//! carries is refused, in words. So what the bytes hold is [`Recorded`], a
//! [`Form`] (`xmip-core-library-codec`'s one binary form) naming each
//! mechanism, after the form's number (`codec::form::numbered`).

use std::borrow::Cow;

use codec::CodecError;
use codec::cursor::Cursor;
use codec::field::{many, optional, place, placed, read_many, read_optional, read_text, text};
use codec::form::{Form, from_numbered, numbered};
use codec::writer::ByteWriter;
use xcore::{Established, Mechanism, PartyId};

use crate::{AlignmentResult, AuthenticatedIdentity, IdentityFacts, UncheckedClaim, Verified};

/// The form's number, the first byte of every record written in it. Form 2
/// keeps the claims no authenticator checked after the alignment; form 3
/// places a verdict among four, `vouched` second.
pub const FORM: u8 = 3;

impl IdentityFacts {
    /// Both identities, their alignment and every unchecked claim, in their
    /// one binary form, after the form's number.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        numbered(&mut out, FORM, &Recorded::of(self));
        out
    }

    /// The facts `bytes` hold in their one binary form, and nothing after
    /// them, each mechanism the one `carried` says the reader carries under
    /// the name recorded.
    ///
    /// # Errors
    ///
    /// Where the bytes are not one — another form, a field cut short, a
    /// number naming nothing, bytes after it — or a mechanism recorded is
    /// not carried.
    pub fn from_record(
        bytes: &[u8],
        carried: impl Fn(&str) -> Option<Mechanism>,
    ) -> Result<Self, CodecError> {
        let recorded: Recorded<'_> = from_numbered(bytes, FORM, "identity facts")?;
        Ok(Self {
            transport: recorded.transport.carried(&carried)?,
            message: recorded
                .message
                .map(|identity| identity.carried(&carried))
                .transpose()?,
            alignment: recorded.alignment,
            unchecked: recorded
                .unchecked
                .into_iter()
                .map(|claim| claim.carried(&carried))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Identity facts as their record holds them, each mechanism by its name.
/// They borrow from the facts they are written from; ones read are owned
/// until a reader that carries each mechanism names it.
struct Recorded<'a> {
    transport: RecordedIdentity<'a>,
    message: Option<RecordedIdentity<'a>>,
    alignment: AlignmentResult,
    unchecked: Vec<RecordedClaim<'a>>,
}

/// An identity as its facts' record holds it.
struct RecordedIdentity<'a> {
    mechanism: Cow<'a, str>,
    value: Cow<'a, str>,
    established: Established,
    verified: Verified,
    party_id: Option<PartyId>,
    evidence: Cow<'a, [(String, String)]>,
    authenticated_at: i128,
}

/// An unchecked claim as its facts' record holds it.
struct RecordedClaim<'a> {
    mechanism: Cow<'a, str>,
    value: Cow<'a, str>,
    established: Established,
}

impl<'a> Recorded<'a> {
    fn of(facts: &'a IdentityFacts) -> Self {
        Self {
            transport: RecordedIdentity::of(&facts.transport),
            message: facts.message.as_ref().map(RecordedIdentity::of),
            alignment: facts.alignment,
            unchecked: facts
                .unchecked
                .iter()
                .map(|claim| RecordedClaim {
                    mechanism: Cow::Borrowed(claim.mechanism.name()),
                    value: Cow::Borrowed(&claim.value),
                    established: claim.established,
                })
                .collect(),
        }
    }
}

impl<'a> RecordedIdentity<'a> {
    fn of(identity: &'a AuthenticatedIdentity) -> Self {
        Self {
            mechanism: Cow::Borrowed(identity.mechanism.name()),
            value: Cow::Borrowed(&identity.value),
            established: identity.established,
            verified: identity.verified,
            party_id: identity.party_id,
            evidence: Cow::Borrowed(&identity.evidence),
            authenticated_at: identity.authenticated_at,
        }
    }

    /// The identity, its mechanism the one `carried` names.
    fn carried(
        self,
        carried: &impl Fn(&str) -> Option<Mechanism>,
    ) -> Result<AuthenticatedIdentity, CodecError> {
        let concluded = "the identity was concluded by";
        let mut identity = AuthenticatedIdentity::new(
            mechanism(carried, &self.mechanism, concluded)?,
            self.value.into_owned(),
            self.established,
            self.verified,
        )
        .at(self.authenticated_at);
        identity.party_id = self.party_id;
        identity.evidence = self.evidence.into_owned();
        Ok(identity)
    }
}

impl RecordedClaim<'_> {
    /// The claim, its mechanism the one `carried` names.
    fn carried(
        self,
        carried: &impl Fn(&str) -> Option<Mechanism>,
    ) -> Result<UncheckedClaim, CodecError> {
        let presented = "an unchecked claim was presented under";
        Ok(UncheckedClaim::new(
            mechanism(carried, &self.mechanism, presented)?,
            self.value.into_owned(),
            self.established,
        ))
    }
}

/// The mechanism the reader carries under `name`, or a refusal saying what
/// was `under` it.
fn mechanism(
    carried: &impl Fn(&str) -> Option<Mechanism>,
    name: &str,
    under: &str,
) -> Result<Mechanism, CodecError> {
    carried(name).ok_or_else(|| {
        CodecError::new(format!(
            "the mechanism '{name}' {under} is not carried here"
        ))
    })
}

impl Form for Recorded<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        self.transport.write(out);
        optional(out, self.message.as_ref(), |out, identity| {
            identity.write(out);
        });
        out.byte(place(&AlignmentResult::ALL, &self.alignment));
        many(out, &self.unchecked, |out, claim| claim.write(out));
    }

    fn read(cursor: &mut Cursor<'_>) -> codec::Result<Self> {
        Ok(Self {
            transport: RecordedIdentity::read(cursor)?,
            message: read_optional(cursor, RecordedIdentity::read)?,
            alignment: placed(&AlignmentResult::ALL, cursor.byte()?, "alignment")?,
            unchecked: read_many(cursor, RecordedClaim::read)?,
        })
    }
}

impl Form for RecordedIdentity<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        text(out, &self.mechanism);
        text(out, &self.value);
        out.byte(place(&Established::ALL, &self.established))
            .byte(place(&Verified::ALL, &self.verified));
        optional(out, self.party_id, |out, party| {
            out.u128_be(party.value());
        });
        many(out, &self.evidence, |out, (name, value)| {
            text(out, name);
            text(out, value);
        });
        out.i128_be(self.authenticated_at);
    }

    fn read(cursor: &mut Cursor<'_>) -> codec::Result<Self> {
        Ok(Self {
            mechanism: Cow::Owned(read_text(cursor)?),
            value: Cow::Owned(read_text(cursor)?),
            established: placed(&Established::ALL, cursor.byte()?, "establishment")?,
            verified: placed(&Verified::ALL, cursor.byte()?, "verification")?,
            party_id: read_optional(cursor, |c| Ok(PartyId::new(c.u128_be()?)))?,
            evidence: Cow::Owned(read_many(cursor, |c| Ok((read_text(c)?, read_text(c)?)))?),
            authenticated_at: cursor.i128_be()?,
        })
    }
}

impl Form for RecordedClaim<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        text(out, &self.mechanism);
        text(out, &self.value);
        out.byte(place(&Established::ALL, &self.established));
    }

    fn read(cursor: &mut Cursor<'_>) -> codec::Result<Self> {
        Ok(Self {
            mechanism: Cow::Owned(read_text(cursor)?),
            value: Cow::Owned(read_text(cursor)?),
            established: placed(&Established::ALL, cursor.byte()?, "establishment")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Alignment;
    use xcore::mechanism;

    fn carried(name: &str) -> Option<Mechanism> {
        [mechanism::circumstance()]
            .into_iter()
            .find(|mechanism| mechanism.name() == name)
    }

    fn facts() -> IdentityFacts {
        let identity = |value: &str| {
            AuthenticatedIdentity::new(
                mechanism::circumstance(),
                value,
                Established::Inferred,
                Verified::Claimed,
            )
            .at(-7)
        };
        IdentityFacts::evaluate(
            Alignment::Strict,
            identity("tcp://127.0.0.1:1")
                .resolving_to(PartyId::new(3))
                .with_evidence("peer", "127.0.0.1 — åäö"),
            Some(identity("ISA06=PARTYX")),
        )
        .with_unchecked([UncheckedClaim::new(
            mechanism::circumstance(),
            "file:///C:/in/order.edi",
            Established::Inferred,
        )])
    }

    /// The bytes `facts()` and the transport identity alone are written as,
    /// taken from the encoder that wrote them before the form was a `Form`
    /// (2026-11-13): the form may not change.
    const FACTS: &str = concat!(
        "030c63697263756d7374616e6365117463703a2f2f3132372e302e302e313a310102010000000000",
        "0000000000000000000003010470656572143132372e302e302e3120e2809420c3a5c3a4c3b6ffff",
        "fffffffffffffffffffffffffff9010c63697263756d7374616e63650c49534130363d5041525459",
        "5801020000fffffffffffffffffffffffffffffff903010c63697263756d7374616e63651766696c",
        "653a2f2f2f433a2f696e2f6f726465722e65646901",
    );
    const ALONE: &str = concat!(
        "030c63697263756d7374616e6365117463703a2f2f3132372e302e302e313a310102010000000000",
        "0000000000000000000003010470656572143132372e302e302e3120e2809420c3a5c3a4c3b6ffff",
        "fffffffffffffffffffffffffff9000000",
    );

    #[test]
    fn the_facts_are_written_byte_for_byte_as_their_form_was() {
        let facts = facts();
        let alone = IdentityFacts::evaluate(Alignment::None, facts.transport.clone(), None);
        for (facts, golden) in [(facts, FACTS), (alone, ALONE)] {
            assert_eq!(codec::hex::encode(&facts.record()), golden);
            let bytes = codec::hex::decode(golden).expect("hex");
            assert_eq!(
                IdentityFacts::from_record(&bytes, carried).expect("read"),
                facts
            );
        }
    }

    #[test]
    fn the_facts_come_back_from_their_record_as_they_were() {
        let facts = facts();
        let record = facts.record();
        assert_eq!(record[0], FORM);
        assert_eq!(
            IdentityFacts::from_record(&record, carried).expect("read"),
            facts
        );
        let alone = IdentityFacts::evaluate(Alignment::None, facts.transport.clone(), None);
        let read = IdentityFacts::from_record(&alone.record(), carried).expect("read");
        assert_eq!(read, alone);
    }

    #[test]
    fn a_mechanism_not_carried_or_bytes_that_are_not_a_record_are_refused() {
        let record = facts().record();
        let refused = IdentityFacts::from_record(&record, |_| None).expect_err("not carried");
        assert!(refused.message.contains("'circumstance'"), "{refused}");
        for cut in [0, 1, record.len() - 1] {
            assert!(IdentityFacts::from_record(&record[..cut], carried).is_err());
        }
        let longer = [record.as_slice(), &[0]].concat();
        assert!(IdentityFacts::from_record(&longer, carried).is_err());
    }
}
