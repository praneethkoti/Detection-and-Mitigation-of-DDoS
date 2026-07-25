.PHONY: demo test lint samples models train clean help

PYTHON ?= python

help:
	@echo "Available targets:"
	@echo "  make demo     run the offline single-command demo (python demo.py)"
	@echo "  make test     run the full pytest suite"
	@echo "  make lint     run ruff check + black --check across the codebase"
	@echo "  make samples  regenerate the PCAP corpus + coordinator replay fixture"
	@echo "  make models   regenerate samples/cicddos2019_sample.csv (synth fallback)"
	@echo "  make train    re-run notebooks/train_pca_and_rf.py -> models/*.joblib"
	@echo "  make clean    remove pytest, bytecode, and ruff caches"

demo:
	$(PYTHON) demo.py

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m black --check .

samples:
	$(PYTHON) scripts/build_sample_pcaps.py --seed 42
	$(PYTHON) scripts/build_coordinator_replay.py

models:
	$(PYTHON) scripts/build_synth_dataset.py --seed 42

train: models
	$(PYTHON) notebooks/train_pca_and_rf.py

clean:
	rm -rf .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
