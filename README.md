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
