# Runtime API direction

Runtime-aware modules receive a shared scan context rather than creating independent state. The compatibility orchestrator prefers the runtime-aware entry point when present and falls back to the legacy module API otherwise.
