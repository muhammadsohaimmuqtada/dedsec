# Maintainer notes

Keep the default branch releasable. Prefer small migration-safe pull requests over broad rewrites, especially in transport, scope, evidence, and correlation code.

Before adding a detector, verify that the same value cannot be obtained by enriching an existing observation or by improving correlation. Feature count is not a substitute for signal quality.
