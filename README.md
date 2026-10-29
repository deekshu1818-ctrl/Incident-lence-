# Incident Lens — HackMITTEN 3.0 prototype

A local Flask prototype for alert ingestion, heuristic correlation, incident-level views, evidence explanations, historical-pattern hints, human-reviewed recommendations, investigation notes, CSV import/export, and a dashboard.

## Run on Windows (VS Code)
1. Extract the ZIP.
2. Open the `incident_lens` folder in VS Code.
3. In Terminal run:

```powershell
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

4. Open `http://127.0.0.1:5000` in your browser.
5. To stop the server, press `Ctrl+C` in the terminal.

If `py` is unavailable, use `python` instead.

## CSV format
Required columns: `timestamp, service, source, severity, message`
Optional columns: `fingerprint, dependency`

Example:
```csv
timestamp,service,source,severity,message,fingerprint,dependency
2026-10-29T08:00:00Z,db-primary,database,critical,Database latency high,db-latency,db-primary
```

Use anonymized demo data. Do not upload customer identifiers, secrets, private IPs, or sensitive production logs to a public demo.

## What the prototype does
- Imports sample alerts from SQLite, with a sample CSV included.
- Groups alerts when the fingerprint or dependency matches within a 20-minute window.
- Shows a probable origin and the evidence behind the grouping.
- Provides a historical-pattern hint and suggested human investigation steps.
- Lets the user save notes and mark incidents reviewed.
- Supports CSV import and export.
- Does **not** connect to real monitoring tools, use a trained ML model, prove root cause, or automatically mute/close/change alerts.

## Important evaluation note
The grouping algorithm is a transparent demo heuristic, not a validated production correlator. Validate precision and recall against ground-truth incident links before claiming performance. Historical match labels are illustrative rules, not real incident-history retrieval.
