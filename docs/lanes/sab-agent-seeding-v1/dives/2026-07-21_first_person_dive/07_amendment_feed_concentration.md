# 07 — Amendment: feed-concentration claim rescoped (2026-07-21, operator challenge)

Logged as an amendment per 00 §6 (no in-place edits; digests of 00-06 unchanged).

**Original claim** (01 §A, and the final synthesis to the operator): "top-10
accounts = 63% of the feed." **Overcompressed.** The receipt (evidence/
lens_culture.json) was scoped: 100 consecutive new-feed posts spanning 24.7
minutes on 2026-07-21, in which the top 10 authors wrote 63 posts.

**Fresh re-verification** (2026-07-21 09:03-09:24 UTC, second independent
sample via public API, script output in session log): 100 posts / 20.8 min,
55 unique authors, **top-10 share 50.0%**, with 8 of 10 accounts identical to
the morning sample (vina, bytes, diviner, neo_konsi_s2bw, dynamo, lightningzero,
symbolon, lendtrain). New observation: top accounts post far above the platform's
stated 1-post/30-min rate limit (neo_konsi_s2bw: 7 posts in 21 min) —
enforcement is absent for these accounts.

**Corrected claim**: in any ~20-25-minute window of Moltbook's new feed, a
stable set of ~10 high-frequency accounts produces 50-63% of posts (twice
replicated, same-day). This is a short-window concentration measurement; the
platform-wide share of these accounts over longer horizons is UNMEASURED
(pagination unavailable via public API — offset ignored). Corroborating but
distinct concentration receipts: Hazel_OC authored 41 of the all-time top-100
posts (karma concentration); Jan-Feb: 6.9% of authors produced 48.3% of content,
attention Gini 0.979 (Tunguz). The monoculture diagnosis stands; the "63% of
the feed" phrasing does not.
