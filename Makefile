PYTHON ?= $(if $(wildcard ../.venv/bin/python),../.venv/bin/python,python3)

.PHONY: bench test-bench

bench:
	$(PYTHON) bench/run.py

test-bench:
	$(PYTHON) -m pytest bench/tests

# --- T12 demo (needs Docker; see docs/demo-script.md) ---
.PHONY: demo-serve demo-check demo-image

demo-serve:
	bash scripts/demo/serve.sh

demo-check:
	bash scripts/demo/check.sh 3

demo-image:
	bash scripts/demo/build_image.sh
