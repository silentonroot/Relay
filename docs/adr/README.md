# Architecture decision records

Each record states one decision, why it was made, what it costs, and the concrete event that
should reopen it. "Accepted" means the code is being built to this decision now. "Proposed" means
the decision is not needed yet; the record holds a recommendation and the evidence still missing.

| ADR                                                 | Title                                            | Status   | Needed by |
| --------------------------------------------------- | ------------------------------------------------ | -------- | --------- |
| [001](ADR-001-trust-boundaries-worker-isolation.md) | Trust boundaries and worker isolation            | Accepted | Phase 1   |
| [002](ADR-002-login-handoff-session-snapshots.md)   | Browser login handoff and session snapshots      | Accepted | Phase 2   |
| [003](ADR-003-local-vault-root-key.md)              | Vault root key for local installs                | Accepted | Phase 2   |
| [004](ADR-004-job-queue.md)                         | Job queue and the threshold for Temporal         | Accepted | Phase 2   |
| [005](ADR-005-policy-representation.md)             | Policy representation                            | Accepted | Phase 1   |
| [006](ADR-006-adapter-packaging-trust.md)           | Adapter packaging, trust and upgrades            | Proposed | Phase 2   |
| [007](ADR-007-mcp-authentication-discovery.md)      | MCP authentication and tool-discovery scoping    | Proposed | Phase 6   |
| [008](ADR-008-model-provider-data-classes.md)       | Model providers and data classes                 | Proposed | Phase 6   |
| [009](ADR-009-audit-integrity.md)                   | Audit integrity                                  | Accepted | Phase 1   |
| [010](ADR-010-tenant-ready-schema.md)               | Tenant-ready schema, single local organization   | Accepted | Phase 1   |
| [011](ADR-011-toolchain.md)                         | Toolchain                                        | Accepted | Phase 1   |
| [012](ADR-012-synthetic-only-dependency-review.md)  | Synthetic-only development and dependency review | Accepted | Phase 0   |
| [013](ADR-013-per-job-sandbox-egress-proxy.md)      | Per-job sandbox and egress proxy                 | Accepted | Phase 2   |

## Writing a new record

Copy the section layout of an existing record: Status, Date, Context, Decision, Alternatives
considered, Consequences, Revisit when. Number it with the next free integer. A record is changed
only to correct an error or to mark it superseded; a new decision gets a new record that links back.

A deviation from the specification in `docs/spec/` is recorded here, in an ADR, before the code
that deviates is merged (specification §22, rule 9).
