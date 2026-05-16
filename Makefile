.PHONY: demo test lint samples clean help

PYTHON ?= python

help:
	@echo "Available targets:"
	@echo "  make demo     run the offline single-command demo (python demo.py)"
	@echo "  make test     run the full pytest suite"
	@echo "  make lint     compile-check every tracked .py file (ruff/black land in Phase 3)"
	@echo "  make samples  regenerate samples/normal.pcap and samples/attack.pcap"
	@echo "  make clean    remove pytest and bytecode caches"

demo:
	$(PYTHON) demo.py

test:
	$(PYTHON) -m pytest

lint:
	@echo "lint: ruff/black config lands in Phase 3 §4.8 — compile-check only for now"
	@$(PYTHON) -m py_compile $$(git ls-files '*.py')

samples:
	$(PYTHON) scripts/build_sample_pcaps.py --seed 42

clean:
	rm -rf .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
