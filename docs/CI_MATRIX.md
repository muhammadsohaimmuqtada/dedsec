# CI matrix

The runtime foundation is tested on Python 3.8, 3.11, and 3.12. Linting runs on Python 3.11 with the development toolchain. The test jobs also run `pip check` and a `dedsec --version` smoke test.
