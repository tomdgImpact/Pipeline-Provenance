# End-to-end suite

Exercises the shipped entry points — the `ppv` executable and real workflow
runs — against the fixture repositories in `tests/fixtures/repos/`. Internal
functions are covered by `tests/unit/`; nothing here reaches inside the package.

Lands with T017 (audit CLI), T022 (pipeline) and T029 (verification).
