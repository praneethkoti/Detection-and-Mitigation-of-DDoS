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
# os.getenv() calls. No streamlit.secrets usage. Phase 4d.1 note: this
# comment used to reference a `--mode tail` path; no such flag was ever
# implemented, and Cloud passes no arguments here anyway, so every option
# in the dashboard is a widget rather than a CLI flag.
#
# If you ever add a feature that needs a secret (private dataset URL,
# API token), do it via streamlit.secrets with the secret values
# configured in the Cloud UI, NOT in this repo.
"""

import dashboard

dashboard.main()
