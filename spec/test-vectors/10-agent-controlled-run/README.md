# Test vector 10 — agent controlled run

One complete controlled agent run, sealed for real by the Sigill test tenant
on 2026-09-18 (standard timestamps, no PQC). It is the design example: the
run `customer-address-change`, agent `contract-agent` v17, control set
`customer-write-v4`, seven events (seq 0 to 6) and one Control Evaluation
with `overall: FAIL` on `status-unchanged`. All payloads are synthetic.

```
10-agent-controlled-run/
├── artifacts/            nine {envelope, signature} files, one per artifact
│   ├── 00-control-artifact.agent-control.json
│   ├── 10-run_start … 16-run_end.agent-execution.json
│   └── 90-control-evaluation.control-evaluation.json
├── objects/              the detached objects (bytes) the artifacts bind
├── objects.json          uri → file
├── canonical/            JCS bytes and SHA-256 of every envelope (byte-stable)
├── expected-result.json  offline verification result for the intact set
├── _generate.py          writes canonical/, asserts hash == signed hashV[0]
└── _validate.py          schema + normative-rule check of the whole set
```

Two vector classes, as `ai-evidence-envelope-v2.md` §11 defines them:

1. **Canonicalization** (`canonical/`): both SDKs must reproduce these bytes
   and digests exactly. CI regenerates them and fails on any drift.
2. **Verification** (`artifacts/` + `objects/`): the signatures are real and
   verify against the Sigill test tenant's certificate. Offline, a verifier
   can check envelope integrity (`hashV[0]`), object completeness, the chain,
   finalization, binding and the evaluation subject; signature validity
   needs the platform or a TS 119 182-1 validator and is `null` in
   `expected-result.json`.

The eight sabotage cases from the design note (byte changed in an object,
event removed, events swapped, `run_end` removed, foreign event inserted,
Control Artifact swapped, evaluation with wrong subject, control set swapped
in the evaluation) are exercised by `Sigill.Sdk.Agent.Tests` against copies
of this set.
