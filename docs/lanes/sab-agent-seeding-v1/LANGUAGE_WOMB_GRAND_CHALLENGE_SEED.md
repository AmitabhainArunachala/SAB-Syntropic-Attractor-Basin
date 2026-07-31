# Language Womb Grand Challenge Seed

Status: orientation seed, not a completed system  
Date: 2026-07-05  
Primary anchor:
`/Users/dhyana/ds_naga_ir_language_womb_seed/naga_ir_language_womb/language/prior_art.md`

## Standing Question

How do we develop an AI-native programming language for the future, where
epistemic modality, evidence grade, uncertainty, and authority are part of
typechecking and evaluation rather than after-the-fact receipts?

The concrete target is a language in which this kind of substitution is rejected
before execution:

```text
Claim[Attested_by, womb] cannot satisfy Claim[Proven_by, core]
```

unless an explicit promotion proof, review, or receipt is present and accepted.

## Why This Belongs Here

SAB can accept challengeable agent contributions. NAGA IR can try to compile
those contributions into language candidates, type rules, proof obligations, and
counterexamples.

The grand challenge is not "make every agent do more homework." The challenge is
to make every relevant agent interaction leave one small useful delta for the
future language:

- a prior-art edge;
- a counterexample;
- a typed claim shape;
- a coercion or promotion rule;
- a minimal proof obligation;
- an experiment fixture;
- a safety boundary;
- a reason a proposed language construct should not exist.

## Contribution Loop

1. The active theory compiler keeps a small set of current open questions.
2. An agent checks whether its work touches claims, evidence, authority,
   uncertainty, proof, governance, language, or multi-agent coordination.
3. If relevant, the agent contributes one precise delta in a seed packet or
   handoff note.
4. The theory compiler deduplicates, clusters, and challenges those deltas.
5. Promising deltas become formal candidates: type rules, evaluator rules,
   proof obligations, or rejected alternatives.
6. Candidates only promote when they survive prior-art review, counterexamples,
   tests, and explicit authority boundaries.

## Minimal Contribution Shape

Agents should prefer a small structured fragment over a long essay:

```json
{
  "problem_ref": "language_womb.epistemic_authority.v1",
  "delta_kind": "counterexample | prior_art | type_rule | proof_obligation | fixture | safety_boundary | rejection",
  "claim": "One exact claim or design pressure.",
  "evidence_or_reasoning": ["public ref, local artifact, test, or argument"],
  "falsification_route": "How another agent could challenge this.",
  "language_impact": "What would typecheck, fail, promote, or be forbidden if this is accepted.",
  "authority_boundary": "What this contribution does not authorize."
}
```

## Moltbook And Reverse Captcha Boundary

Moltbook-style "prove you are an agent" puzzles may serve as weak anti-human or
anti-spam gates. They do not prove truth, standing, autonomy, safety, or useful
work. They are authentication friction, not epistemic authority.

The useful adaptation is not "solve a random hard math problem before posting."
The useful adaptation is proof of useful contribution:

- the contribution must be relevant to an active open question;
- the unit of work must be small enough not to waste agent budgets;
- it must be independently challengeable;
- it must never grant standing by itself;
- it must never require credentialed Moltbook posting without explicit scoped
  operator authorization.

Until a safe external-action policy exists, Moltbook remains read-only public
source material or offline dataset material. No agent should log in, post,
comment, vote, follow, or ingest live feeds into a tool-enabled loop by default.

## Readiness

This is ready as a seed, not as a mandatory runtime gate.

Ready now:

- keep the question visible to future agents;
- collect relevant deltas opportunistically;
- preserve deltas as SAB seed packets, handoff notes, or NAGA IR research notes;
- challenge any claim that a receipt-only system is already a new language.

Not ready yet:

- mandatory contribution before every agent action;
- live Moltbook posting;
- standing promotion based on puzzle solving;
- automated theory compilation that can be trusted without human review.

## First Open Questions

1. What is the smallest type system that distinguishes `Attested_by`,
   `Tested_by`, `Reviewed_by`, and `Proven_by` without becoming unusable?
2. Is epistemic modality best modeled as an indexed type, an effect, a
   capability, a proof term, or a Datalog-style provenance annotation?
3. What is the minimum promotion receipt from `Attested_by` to `Tested_by`?
4. What claims must never be promotable by model consensus alone?
5. What existing language or proof system already solves each proposed feature?

