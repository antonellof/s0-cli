# Run 2026-04-19T15-17-59Z__v1_single_shot_c1__3bb0
- harness: `v1_single_shot_c1`
- target: `bench:7 tasks`
- invocation: `s0 optimize iter=1 slot=c1 harness=v1_single_shot_c1`
- model: `openai/gpt-4o-mini`
- ended_via: `aggregated`
- findings: 13 (high:7, medium:6)
- usage: {'input_tokens': 4451, 'output_tokens': 1259, 'cached_input_tokens': 0, 'turns': 7}

## Score
```json
{
  "tp": 5,
  "fp": 8,
  "fn": 3,
  "precision": 0.3846,
  "recall": 0.625,
  "f1": 0.4762,
  "input_tokens": 4451,
  "output_tokens": 1259,
  "cached_input_tokens": 0,
  "turns": 7
}
```

_Harness:_ Single-shot triage with reduced token usage.
