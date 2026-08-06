# Migration guarantees

The runtime migration should not silently change a detector from candidate to verified, weaken TLS defaults, expand target scope, or increase unbounded request volume. Any such behavior change must be explicit, reviewed, and tested.
