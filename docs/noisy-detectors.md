# Detector verification backlog

The following detector classes should be migrated early because heuristic output can otherwise be misread as a verified vulnerability:

- rate-limit observations
- clickjacking/framing posture
- CORS configuration behavior
- subdomain takeover fingerprints
- redirect candidates
- sensitive-file exposure candidates

Each migration should define negative controls, candidate semantics, and an explicit verified state.
