"""Streamlit Community Cloud entry shim (Phase 4a §4a.K).

Cloud's deploy convention is `streamlit_app.py` at repo root. This file
exists so the Cloud deploy points at it; the actual dashboard logic lives
in dashboard.py and is unchanged across the two entry paths
(`streamlit run dashboard.py` locally vs Community Cloud).

# NO SECRETS, NO ENV VARS, NO API KEYS.
#
# Streamlit Community Cloud is PUBLIC HOSTING. Anything stored alongside
# this file is world-readable. The dashboard reads only world-readable
# committed files (samples/*.pcap, models/*.joblib, config.yaml). No
# os.getenv() calls. No streamlit.secrets usage. The `--mode tail` path
# would read $telemetry_path from config, but that path is `-` (stdout)
# by default — Cloud users hit the replay path, never tail.
#
# If you ever add a feature that needs a secret (private dataset URL,
# API token), do it via streamlit.secrets with the secret values
# configured in the Cloud UI — NOT in this repo.
"""

import dashboard

dashboard.main()
