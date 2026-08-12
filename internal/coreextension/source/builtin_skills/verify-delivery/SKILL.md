---
name: dirextalk-verify-delivery
description: Verify that a feature, fix, build, or deployment is genuinely complete using observable acceptance evidence. Use for release readiness, regression testing, operational handoff, and claims that something works end to end.
---

# Verify Delivery

## Workflow

1. Convert the request into observable acceptance criteria and explicit non-goals.
2. Verify the smallest real consumer path before broad tests; distinguish unit evidence from production-like evidence.
3. Exercise success, expected rejection, and infrastructure failure separately.
4. Check durable state, side effects, cleanup, retries, and restart behavior where they matter.
5. Record exact versions or immutable digests for tested artifacts without exposing secrets.
6. Report what passed, what was not exercised, and any blocker that prevents an honest completion claim.

## Guardrails

- Do not treat a mocked helper as proof of the real wrapper or deployment path.
- Do not silently retry an uncertain mutation or broaden authorization to make a test pass.
- Do not describe partial evidence as an end-to-end success.
- Keep test artifacts bounded and clean up resources created for verification.
