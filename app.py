from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from pathlib import Path
import sqlite3, csv, json, re
from datetime import datetime, timedelta, timezone
import pandas as pd

BASE = Path(__file__).resolve().parent
DB = BASE / 'data' / 'incident_lens.db'
CSV_PATH = BASE / 'data' / 'alerts.csv'
app = Flask(__name__)
app.secret_key = 'incident-lens-demo-change-me'

SAMPLE_ALERTS = [
 ('2026-10-29T08:00:00Z','db-primary','database','critical','Database response time above threshold','db-latency', 'db-primary'),
 ('2026-10-29T08:01:00Z','checkout-api','api','high','Checkout API latency elevated','api-latency','db-primary'),
 ('2026-10-29T08:02:00Z','payments','service','high','Payment error rate increased','error-rate','db-primary'),
 ('2026-10-29T08:03:00Z','catalog-api','api','medium','Catalog requests slower than normal','api-latency','db-primary'),
 ('2026-10-29T08:04:00Z','web-gateway','gateway','high','Gateway 5xx responses elevated','error-rate','db-primary'),
 ('2026-10-29T08:10:00Z','worker-queue','worker','medium','Queue processing delay','queue-delay','worker-queue'),
 ('2026-10-29T08:11:00Z','email-worker','service','low','Email job duration increased','queue-delay','worker-queue'),
 ('2026-10-29T08:15:00Z','auth-service','service','critical','Authentication failures above baseline','auth-failure','auth-service'),
 ('2026-10-29T08:16:00Z','login-api','api','high','Login API 401/5xx spike','auth-failure','auth-service'),
 ('2026-10-29T08:20:00Z','storage-node-4','infrastructure','medium','Disk utilization reached warning threshold','disk-usage','storage-node-4'),
 ('2026-10-29T08:23:00Z','recommendation-api','api','low','Response time mildly elevated','api-latency','recommendation-api'),
 ('2026-10-29T08:25:00Z','edge-proxy','gateway','high','Unusual connection reset rate','connection-reset','edge-proxy'),
 ('2026-10-29T08:26:00Z','customer-status','status-page','high','Customer-facing degradation reported','status-degradation','db-primary'),
 ('2026-10-29T08:29:00Z','db-replica','database','medium','Replication lag increased','db-latency','db-primary'),
 ('2026-10-29T08:35:00Z','batch-runner','worker','low','Scheduled batch completed slowly','job-duration','batch-runner'),
]

def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, service TEXT NOT NULL,
            source TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
            fingerprint TEXT NOT NULL, dependency TEXT NOT NULL, incident_id INTEGER,
            reviewed INTEGER NOT NULL DEFAULT 0)''')
        con.execute('''CREATE TABLE IF NOT EXISTS incident_notes (
            incident_id INTEGER PRIMARY KEY, note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)''')
        count = con.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        if count == 0:
            for row in SAMPLE_ALERTS:
                con.execute('INSERT INTO alerts(timestamp,service,source,severity,message,fingerprint,dependency) VALUES(?,?,?,?,?,?,?)', row)
    refresh_correlation()

def get_alerts():
    with connect() as con:
        rows = con.execute('SELECT * FROM alerts ORDER BY timestamp DESC').fetchall()
    return [dict(r) for r in rows]

def parse_time(value):
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00'))
    except Exception:
        return datetime.now(timezone.utc)

def refresh_correlation():
    """Transparent demo correlation: shared dependency OR fingerprint, within 20 minutes.
    This is a heuristic, not proof of causation."""
    with connect() as con:
        rows = [dict(r) for r in con.execute('SELECT * FROM alerts ORDER BY timestamp').fetchall()]
        # Union-find for related alerts.
        parent = {r['id']: r['id'] for r in rows}
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]; x = parent[x]
            return x
        def union(a,b):
            ra, rb = find(a), find(b)
            if ra != rb: parent[rb] = ra
        for i, a in enumerate(rows):
            for b in rows[i+1:]:
                dt = abs((parse_time(a['timestamp']) - parse_time(b['timestamp'])).total_seconds())
                if dt > 20*60: continue
                same_fingerprint = a['fingerprint'] == b['fingerprint']
                shared_dependency = a['dependency'] == b['dependency'] and a['dependency'] not in ('', None)
                if same_fingerprint or shared_dependency: union(a['id'], b['id'])
        groups = {}
        for r in rows: groups.setdefault(find(r['id']), []).append(r)
        con.execute('UPDATE alerts SET incident_id=NULL')
        # Assign stable group IDs by minimum alert id; dashboard only depends on current grouping.
        for group in groups.values():
            group_id = min(x['id'] for x in group)
            con.executemany('UPDATE alerts SET incident_id=? WHERE id=?', [(group_id, x['id']) for x in group])

def incident_views():
    alerts = get_alerts()
    groups = {}
    for a in alerts:
        key = a['incident_id'] or a['id']
        groups.setdefault(key, []).append(a)
    output = []
    for key, items in groups.items():
        items.sort(key=lambda x: x['timestamp'])
        sev_order = {'critical':4,'high':3,'medium':2,'low':1,'info':0}
        top = max(items, key=lambda x: sev_order.get(x['severity'].lower(),0))
        # Explainable evidence-based heuristic: earliest alert + dependency frequency.
        dep_counts = {}
        for a in items: dep_counts[a['dependency']] = dep_counts.get(a['dependency'],0)+1
        likely_dep = max(dep_counts, key=dep_counts.get)
        root = items[0]
        if likely_dep and dep_counts[likely_dep] > 1:
            root = next((a for a in items if a['dependency'] == likely_dep and a['source'] in ('database','infrastructure')), items[0])
        evidence = [f"{len(items)} alerts grouped by shared fingerprint or dependency within a 20-minute window.",
                    f"Earliest observed alert: {items[0]['timestamp']} ({items[0]['service']}).",
                    f"Most common dependency label: {likely_dep} ({dep_counts[likely_dep]} alert(s))."]
        # Example historical pattern only; explicitly heuristic and not a real ground-truth record.
        historical = 'Possible match: database latency / downstream service degradation' if any('db' in a['fingerprint'] or 'db' in a['dependency'] for a in items) else 'No strong historical pattern in demo rules; review as potentially novel.'
        recommendation = 'Check the probable origin and dependency health; verify metrics before tuning alerts.' if top['severity'] in ('critical','high') else 'Review whether this pattern is actionable; consider threshold tuning only after validation.'
        output.append({'id':key,'count':len(items),'services':sorted(set(a['service'] for a in items)), 'severity':top['severity'],
            'title': root['message'] if len(items)>1 else items[0]['message'], 'root_service':root['service'],
            'first_seen':items[0]['timestamp'],'last_seen':items[-1]['timestamp'],'alerts':items,'evidence':evidence,
            'historical':historical,'recommendation':recommendation,'reviewed':all(a['reviewed'] for a in items)})
    return sorted(output, key=lambda x: ({'critical':0,'high':1,'medium':2,'low':3}.get(x['severity'],4), -x['count']))

@app.route('/')
def dashboard():
    incidents = incident_views()
    alerts = get_alerts()
    total = len(alerts)
    distinct = len(incidents)
    critical = sum(1 for i in incidents if i['severity'] == 'critical')
    novel = sum(1 for i in incidents if i['historical'].startswith('No strong'))
    return render_template('index.html', incidents=incidents, total=total, distinct=distinct, critical=critical, novel=novel, alerts=alerts[-8:][::-1])

@app.route('/incident/<int:incident_id>')
def incident_detail(incident_id):
    incident = next((x for x in incident_views() if x['id'] == incident_id), None)
    if not incident: return 'Incident not found', 404
    with connect() as con:
        note = con.execute('SELECT note FROM incident_notes WHERE incident_id=?',(incident_id,)).fetchone()
    return render_template('incident.html', incident=incident, note=note['note'] if note else '')

@app.route('/incident/<int:incident_id>/review', methods=['POST'])
def mark_reviewed(incident_id):
    with connect() as con:
        con.execute('UPDATE alerts SET reviewed=1 WHERE incident_id=?',(incident_id,))
    flash('Incident marked as reviewed. No alerts were muted or modified.')
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/incident/<int:incident_id>/note', methods=['POST'])
def save_note(incident_id):
    note = request.form.get('note','').strip()[:2000]
    with connect() as con:
        con.execute('INSERT INTO incident_notes(incident_id,note,updated_at) VALUES(?,?,?) ON CONFLICT(incident_id) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at',(incident_id,note,datetime.now(timezone.utc).isoformat()))
    flash('Investigation note saved locally.')
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/upload', methods=['POST'])
def upload_csv():
    file = request.files.get('file')
    if not file or not file.filename.lower().endswith('.csv'):
        flash('Please choose a CSV file.'); return redirect(url_for('dashboard'))
    try:
        df = pd.read_csv(file)
        required = {'timestamp','service','source','severity','message'}
        if not required.issubset(set(df.columns)):
            flash('CSV must include columns: timestamp, service, source, severity, message. Optional: fingerprint, dependency.'); return redirect(url_for('dashboard'))
        records=[]
        for _, r in df.fillna('').iterrows():
            msg = str(r['message'])[:500]
            fingerprint = str(r.get('fingerprint') or re.sub(r'\d+', '#', msg.lower())[:80])
            dependency = str(r.get('dependency') or r['service'])
            records.append((str(r['timestamp']),str(r['service'])[:120],str(r['source'])[:80],str(r['severity']).lower(),msg,fingerprint,dependency))
        with connect() as con:
            con.execute('DELETE FROM alerts')
            con.executemany('INSERT INTO alerts(timestamp,service,source,severity,message,fingerprint,dependency) VALUES(?,?,?,?,?,?,?)',records)
        refresh_correlation(); flash(f'Imported {len(records)} alerts and recalculated demo correlations.')
    except Exception as exc:
        flash(f'Could not import CSV: {exc}')
    return redirect(url_for('dashboard'))

@app.route('/api/incidents')
def api_incidents(): return jsonify(incident_views())

@app.route('/export')
def export_csv():
    from flask import Response
    rows = get_alerts()
    if not rows: return 'No alerts', 404
    import io
    out = io.StringIO(); writer = csv.DictWriter(out, fieldnames=list(rows[0].keys())); writer.writeheader(); writer.writerows(rows)
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=incident_lens_alerts.csv'})

@app.route('/reset', methods=['POST'])
def reset_demo():
    with connect() as con:
        con.execute('DELETE FROM alerts'); con.execute('DELETE FROM incident_notes')
        for row in SAMPLE_ALERTS: con.execute('INSERT INTO alerts(timestamp,service,source,severity,message,fingerprint,dependency) VALUES(?,?,?,?,?,?,?)',row)
    refresh_correlation(); flash('Demo dataset restored.'); return redirect(url_for('dashboard'))

init_db()
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
