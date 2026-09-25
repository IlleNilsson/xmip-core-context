# xmip-core-context

Message Context: what accumulates as a Message is handled. Promoted
properties land here as text, and so does the identity a Message arrived
with — both layers of it, per ADR-0019 clause 6.

Context is not content. Content is immutable and context accumulates; a value
promoted into context drives Subscription evaluation without the content being
parsed again. Context does not hold the Stream and does not decide anything
itself: promotion writes it, routing reads it.

`doc/architecture/runtime-model.md` section 9 (promotion, demotion and the
content selectors) and `module-model.md` section 2 govern it;
`architecture.toml` carries the maturity.

## The names that cross a boundary

`context::property` holds every name a property travels under when one layer
writes it and another reads it: what a transport says about an arrival — the
peer's address and hardware address, HTTP's headers, query, form, method and
target, the TLS peer certificate, the SSH public-key exchange, the first two
NTLM legs — which the identity gates read, and the Party the runtime writes
into the Message Context, which a route reads. One declaration each, below
both sides. Until 2026-09-24 the peer's address was
`xmip-core-library-net`'s, the SSH names were declared by the SFTP transport
and again by both `ssh-key` gates, and the runtime wrote `xmip.party` as a
literal (the owner, 2026-09-24; ADR-0019, amendment 2026-09-24). A name the
identity gates hand one another and nobody else writes stays
`identify::evidence`.

A header, whichever protocol carried it, travels under
`<protocol>.header.<name>` — `http.header.content-type`,
`amqp.header.x-priority`, `kafka.header.Trace-Id` — on the arrival and in the
Message Context alike. The name is in lower case only where the protocol's
specification folds it: `property::HEADER_CASE_FOLDING` is the one table of
those protocols (HTTP and what rides on it, SSDP, the mail protocols and MIME,
SIP), each cited to its clause; every other protocol keeps the name as
written, so Kafka's `Trace-Id` and `trace-id` stay two headers. `property::header` builds that name and is the only
place it is spelled; the well-known HTTP header names are built from the same
spelling, a transport that writes a header calls it, and the identity gates
and `route/header` read through it (the owner, 2026-09-24; ADR-0019,
amendment 2026-09-24).
