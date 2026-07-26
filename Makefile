# Dharmic Agora / SAB — agent orientation commands
# Run `make help` to see the supported read-only entrypoints.

PYTHON ?= python3
SAB_ORIENT_AGENT ?= agent
SAB_ORIENT_RECEIPT ?= $(HOME)/.dharma/sab/latest_preflight_$(SAB_ORIENT_AGENT).json

.PHONY: help sab-orient sab-orient-strict orient

help:
	@printf '%s\n' \
		'make sab-orient                  Explain SAB, entrypoints, canonical files, and live truth' \
		'make sab-orient ARGS=--json      Emit sab.orientation.v1 JSON' \
		'make sab-orient ARGS=--no-live   Orient from source without network access' \
		'make sab-orient-strict            Require live recruitment readiness and write a private receipt' \
		'make orient                      Compatibility alias for make sab-orient'

# Read-only projection. It never registers, submits, moderates, deploys, or writes
# repository state. Network probes use normal TLS verification.
sab-orient:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/sab_orient.py $(ARGS)

sab-orient-strict:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/sab_orient.py \
		--strict-live --write-receipt $(SAB_ORIENT_RECEIPT) $(ARGS)

# SAB-local compatibility alias. Dharma Swarm's own `make orient` remains its
# whole-organism projection; inside this repository, orient means SAB.
orient: sab-orient
