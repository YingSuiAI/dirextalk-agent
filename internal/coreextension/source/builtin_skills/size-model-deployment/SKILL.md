---
name: dirextalk-size-model-deployment
description: Size hardware for model inference or training deployments using exact model artifacts, runtime compatibility, accelerator memory, system memory, storage, context, and concurrency. Use before recommending a server or proposing a paid Cloud Worker for an AI model workload.
---

# Size Model Deployment

Produce a sourced capacity decision for the exact workload, not a generic GPU recommendation.

## Establish the workload

- Resolve the exact model tag or immutable artifact, quantization/precision, and published download size. Do not size from a model family name or a floating `latest` tag.
- Identify inference or training, runtime and version, operating system, accelerator backend and driver requirements, context length, expected concurrency, latency goal, and whether CPU offload is permitted.
- Use current primary sources for model artifacts, runtime compatibility, and provider instance specifications. Record material unknowns instead of guessing them.

## Calculate independent minima

- Accelerator memory: resident model weights plus KV cache or training state, runtime workspace, concurrent requests, and explicit headroom. A fractional GPU contributes only its assigned memory, not the full physical card.
- System memory: CPU-resident or offloaded weights, model loading and conversion peaks, runtime processes, operating system, and headroom. Never silently assume CPU offload; state its performance consequence when it is allowed.
- Storage: downloads, expanded or converted model copies, runtime caches, temporary files, logs, outputs, and update or rollback headroom. A disk that only fits the advertised download is insufficient.
- CPU and network: preprocessing, tokenization, request concurrency, model downloads, and any distributed traffic. Treat these as separate constraints from accelerator capacity.

Do not equate artifact size directly with accelerator memory unless the exact runtime and loading strategy justify it. Show calculations or a defensible bounded estimate for every hard minimum.

## Select and report

Choose an instance only after verifying that its assigned accelerator memory, accelerator/runtime compatibility, system memory, CPU, disk, architecture, and regional availability satisfy every hard minimum. Compare eligible shapes by cost only after this fit check.

Report:

1. The verified model artifact and runtime assumptions.
2. Hard minimum and recommended capacity for each resource, with headroom identified separately.
3. The selected instance's exact assigned resources and a pass/fail comparison against every minimum.
4. Sources, calculation assumptions, and any remaining uncertainty.

If an exact artifact or a critical compatibility/capacity fact cannot be verified, do not recommend or propose a paid server. Explain what must be resolved first.
