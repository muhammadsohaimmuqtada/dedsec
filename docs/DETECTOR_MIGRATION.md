# Detector migration priorities

HTTP-heavy detectors should move to the shared runtime before new coverage is added. The highest-priority migrations are CORS, redirect, rate-limit, clickjacking/framing posture, exposure checks, and API-schema discovery because they currently mix transport behavior with detector logic or can produce easily over-interpreted signals.
