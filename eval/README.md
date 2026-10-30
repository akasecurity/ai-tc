# Evals

Replays of attacks from public research, run against the built plugin. Each folder holds a
README, `eval.yaml`, the cases and its run command; `results/` is git-ignored.

| Folder                                                                            | Last run                 | Source                       | Attack                                                                                                                                 | Goal  | Result                                                                                                                     |
| --------------------------------------------------------------------------------- | ------------------------ | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------- |
| [2026-10-28-forever-downloads-agents-md](2026-10-28-forever-downloads-agents-md/) | 2026-10-29, ai-tc 0.9.21 | Forever Security, 2026-10-22 | Agent instructions dropped in a Downloads folder tamper with the agent harness                                                         | block | 7 of 7 attack calls blocked with `agent-harness-tamper` on Block, 0 of 5 look-alikes flagged; default install detects only |
| [2026-10-29-cohere-agent-egress](2026-10-29-cohere-agent-egress/)                 | 2026-10-30, ai-tc 0.9.22 | Cohere, 2026-10-26           | An open-weight agent uploads to object storage, fetches from a file proxy, reads cloud metadata and escalates through a user namespace | block | 12 of 12 attack calls blocked with `agent-egress` on Block, 0 of 8 look-alikes flagged; default install detects only       |

Add a row in the same PR as the eval, and update its Last run and Result on every published re-run.
