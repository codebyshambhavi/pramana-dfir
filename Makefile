PYTHON ?= $(if $(wildcard ../.venv/bin/python),../.venv/bin/python,python3)

.PHONY: bench test-bench

bench:
	$(PYTHON) bench/run.py

test-bench:
	$(PYTHON) -m pytest bench/tests
