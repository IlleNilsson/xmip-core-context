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
