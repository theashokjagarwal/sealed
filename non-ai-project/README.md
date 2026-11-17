# Order Fulfillment Service

Standard deterministic microservice for order aggregation, tax computation, and status processing.

## Tech Stack
- Python 3.10+
- PostgreSQL
- pytest / unittest

## Design Notes
- 100% deterministic calculation logic.
- Zero AI / ML components or external LLM API dependencies.
- Secrets injected via environment variables only.
