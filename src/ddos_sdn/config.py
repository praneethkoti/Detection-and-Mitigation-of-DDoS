"""Runtime configuration loader for ddos_sdn.

Resolution order (highest precedence first):
    1. explicit path argument to load_config(...)
    2. $DDOS_SDN_CONFIG_FILE environment variable
    3. config.yaml in the parent of this package's install location
       (i.e. the repository root for editable installs)
    4. DEFAULTS dict compiled into this module

The DEFAULTS path is what makes unit tests trivial: an EntropyAnalyzer
or pox_controller imported in a test context will see well-formed config
without anyone having to drop a YAML file on disk.

Keeping the loader pure-stdlib avoids a hard dependency on PyYAML for
test-only paths. PyYAML is consulted only if a YAML file actually has
to be parsed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "detector": {
        "window_packets": 250,
        "entropy_threshold_bits": 1.66,
        "port_count_threshold": 50,
        "timer_interval_seconds": 2,
        "pca": {
            "model_path": "models/pca.joblib",
            "benign_distance_percentile": 99,
        },
        "rf": {
            "model_path": "models/rf.joblib",
            "proba_threshold": 0.5,
        },
    },
    "controller": {
        "arp_entry_timeout_seconds": 120,
        "flow_mod_hard_timeout_seconds": 30,
    },
    "telemetry": {
        "format": "jsonl",
        "path": "-",
        "fields": [
            "t",
            "window_packets",
            "entropy_dst",
            "entropy_src",
            "entropy_size",
            "pps",
            "pca_mahalanobis",
            "rf_proba",
            "verdict_entropy",
            "verdict_pca",
            "verdict_rf",
            "top_dst",
            "top_src",
        ],
    },
}

ENV_VAR = "DDOS_SDN_CONFIG_FILE"


def _repo_root_yaml() -> Path:
    # src/ddos_sdn/config.py  -> repo root is two parents up from src/
    here = Path(__file__).resolve()
    return here.parent.parent.parent / "config.yaml"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _parse_yaml(path: Path) -> dict[str, Any]:
    import yaml  # local import: PyYAML is only needed when a real file exists

    with path.open("r", encoding="utf-8") as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return loaded


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Return the effective configuration dict.

    File-sourced values are deep-merged onto DEFAULTS so partial config files
    are valid: a YAML containing only `detector.window_packets` overrides that
    one key and leaves everything else at defaults.
    """
    candidates: list[Path] = []
    if path is not None:
        candidates.append(Path(path))
    env_value = os.environ.get(ENV_VAR)
    if env_value:
        candidates.append(Path(env_value))
    repo_yaml = _repo_root_yaml()
    if repo_yaml.is_file():
        candidates.append(repo_yaml)

    for candidate in candidates:
        if candidate.is_file():
            overrides = _parse_yaml(candidate)
            return _deep_merge(DEFAULTS, overrides)

    return _deep_merge(DEFAULTS, {})  # returns a fresh copy
