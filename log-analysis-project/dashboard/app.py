"""
Plotly Dash dashboard for visualizing brute-force detection results.

Features:
- Summary KPI cards
- Histogram of failed logins by IP
- Time-series of failed logins
- World map scatter (mock geolocation)
- Interactive table of brute-force alerts

To run:
    python -m dashboard.app
Open http://127.0.0.1:8050 in your browser.
"""

import os
import pandas as pd
from dash import Dash, dcc, html, dash_table, Input, Output
import plotly.express as px
from scripts.extract_events import extract
from scripts.detect_bruteforce import detect_bruteforce
from scripts.anomaly_detection import detect_anomalous_ips
from scripts.geolocation import geo_lookup
from scripts.utils import get_logger
from dashboard.components import kpi_card

logger = get_logger("dashboard")

# Prepare data (extract events if necessary)
EVENTS_CSV = "events_extracted.csv"
if not os.path.exists(EVENTS_CSV):
    events_df = extract()
else:
    events_df = pd.read_csv(EVENTS_CSV, parse_dates=["timestamp"])
alerts_df = detect_bruteforce(events_df)
anomalies_df = detect_anomalous_ips(events_df, window_minutes=120, contamination=0.1)

# Build geolocation DataFrame for plotting
fails = events_df[events_df["event_type"] == "failed_login"].copy()
geo_rows = []
for _, r in fails.iterrows():
    ip = r["ip"]
    geo = geo_lookup(ip)
    geo_rows.append({
        "ip": ip,
        "username": r["username"],
        "timestamp": r["timestamp"],
        "country": geo["country"],
        "region": geo["region"],
        "city": geo["city"],
        "lat": geo["lat"],
        "lon": geo["lon"]
    })
geo_df = pd.DataFrame(geo_rows).drop_duplicates(subset=["ip", "lat", "lon"])

# Create figures
if not fails.empty:
    hist = px.histogram(fails, x="ip", title="Failed Logins by IP")
    ts_df = fails.set_index(pd.to_datetime(fails["timestamp"]))
    ts_counts = ts_df.resample("1T").size().rename("count").reset_index()
    ts_plot = px.line(ts_counts, x="timestamp", y="count", title="Failed Logins Over Time (1min)")
else:
    hist = px.histogram()
    ts_plot = px.line()

if not geo_df.empty:
    world = px.scatter_geo(geo_df, lat="lat", lon="lon", hover_name="ip", scope="world", title="Attacker Geolocation (mock)")
else:
    world = px.scatter_geo()

# Dash App layout
app = Dash(__name__, title="Brute-force Detection Dashboard")

app.layout = html.Div(children=[
    html.H2("Windows Log Brute-Force Detection Dashboard"),
    html.Div([
        html.Div(kpi_card("Total Events", str(len(events_df)), "Events analyzed"), style={"width": "24%", "display": "inline-block", "padding": "8px"}),
        html.Div(kpi_card("Failed Logins", str(len(fails)), "Total failures"), style={"width": "24%", "display": "inline-block", "padding": "8px"}),
        html.Div(kpi_card("Unique IPs", str(events_df["ip"].nunique()), ""), style={"width": "24%", "display": "inline-block", "padding": "8px"}),
        html.Div(kpi_card("Alerts", str(len(alerts_df)), "Brute-force alerts"), style={"width": "24%", "display": "inline-block", "padding": "8px"}),
    ], style={"display": "flex", "flexWrap": "wrap"}),

    html.Div([
        html.Div(dcc.Graph(figure=hist), style={"width": "48%", "display": "inline-block", "padding": "8px"}),
        html.Div(dcc.Graph(figure=ts_plot), style={"width": "48%", "display": "inline-block", "padding": "8px"}),
    ]),

    html.Div([
        html.Div(dcc.Graph(figure=world), style={"width": "100%", "padding": "8px"}),
    ]),

    html.H3("Brute-force Alerts"),
    dash_table.DataTable(
        id="alerts-table",
        columns=[{"name": c, "id": c} for c in (alerts_df.columns.tolist() if not alerts_df.empty else ["flag_type","flag_value","first_seen","last_seen","count"])],
        data=alerts_df.to_dict("records") if not alerts_df.empty else [],
        page_size=10,
        style_table={"overflowX": "auto"},
    ),

    html.Div([
        html.Button("Refresh Data", id="refresh-btn", n_clicks=0),
        html.Button("Generate PDF Report", id="pdf-btn", n_clicks=0),
        html.Div(id="action-output")
    ], style={"padding": "12px"})
])


@app.callback(
    Output("action-output", "children"),
    Input("refresh-btn", "n_clicks"),
    Input("pdf-btn", "n_clicks")
)
def on_action(refresh_clicks, pdf_clicks):
    ctx = dash.callback_context
    if not ctx.triggered:
        return ""
    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    if button_id == "refresh-btn":
        # reload data
        global events_df, alerts_df, anomalies_df
        if os.path.exists(EVENTS_CSV):
            events_df = pd.read_csv(EVENTS_CSV, parse_dates=["timestamp"])
        else:
            events_df = extract()
        alerts_df = detect_bruteforce(events_df)
        anomalies_df = detect_anomalous_ips(events_df)
        return "Data refreshed."
    if button_id == "pdf-btn":
        # generate PDF synchronously (for demo)
        from scripts.generate_report import generate_pdf_report
        pdf_path = generate_pdf_report()
        return f"Generated PDF: {pdf_path}"
    return ""


def run():
    app.run_server(debug=True)


if __name__ == "__main__":
    run()