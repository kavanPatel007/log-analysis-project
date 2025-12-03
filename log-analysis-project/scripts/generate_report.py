"""
PDF report generator.

- Reads events and alerts
- Produces charts as PNGs (matplotlib/plotly)
- Renders a PDF with high-level metrics, charts, and table of alerted brute-force attempts

Uses reportlab for PDF generation.
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from .extract_events import extract
from .detect_bruteforce import detect_bruteforce
from .anomaly_detection import detect_anomalous_ips
from .geolocation import geo_lookup
from .utils import get_logger

logger = get_logger("generate_report")


def create_charts(df, outdir="reports_assets"):
    """
    Create and save charts used in the PDF.
    Returns dict of image filenames.
    """
    os.makedirs(outdir, exist_ok=True)
    assets = {}

    # Histogram: failed logins by IP
    fails = df[df["event_type"] == "failed_login"]
    hist_path = os.path.join(outdir, "hist_failures_by_ip.png")
    if not fails.empty:
        counts = fails.groupby("ip").size().sort_values(ascending=False)
        plt.figure(figsize=(8, 4))
        counts.plot(kind="bar", color="crimson")
        plt.title("Failed logins by IP")
        plt.xlabel("IP")
        plt.ylabel("Failed count")
        plt.tight_layout()
        plt.savefig(hist_path, dpi=150)
        plt.close()
    else:
        # placeholder empty chart
        plt.figure(figsize=(8, 4))
        plt.text(0.5, 0.5, "No failed logins", ha="center")
        plt.axis("off")
        plt.savefig(hist_path, dpi=150)
        plt.close()
    assets["hist_failures_by_ip"] = hist_path

    # Time-series: failed logins over time
    ts_path = os.path.join(outdir, "ts_failures.png")
    if not fails.empty:
        ts = fails.set_index(pd.to_datetime(fails["timestamp"]))
        ts_count = ts.resample("1T").size()
        plt.figure(figsize=(10, 3))
        ts_count.plot(linewidth=2)
        plt.title("Failed logins over time (1 minute buckets)")
        plt.xlabel("Time")
        plt.ylabel("Failed count")
        plt.tight_layout()
        plt.savefig(ts_path, dpi=150)
        plt.close()
    else:
        plt.figure(figsize=(10, 3))
        plt.text(0.5, 0.5, "No failed logins to plot", ha="center")
        plt.axis("off")
        plt.savefig(ts_path, dpi=150)
        plt.close()
    assets["ts_failures"] = ts_path

    # World map scatter (very simple using scatter plot with mock geolocations)
    world_path = os.path.join(outdir, "world_map.png")
    # Build scatter from unique failed IPs with geolocation
    positions = []
    for ip in fails["ip"].dropna().unique():
        g = geo_lookup(ip)
        positions.append((g["lon"], g["lat"], ip))
    plt.figure(figsize=(8, 4))
    if positions:
        lons = [p[0] for p in positions]
        lats = [p[1] for p in positions]
        plt.scatter(lons, lats, s=50, c="red", alpha=0.7)
        for lon, lat, ip in positions:
            plt.text(lon + 0.5, lat + 0.5, ip, fontsize=8)
        plt.title("Attacker Geolocation (mock data)")
        plt.xlabel("Longitude")
        plt.ylabel("Latitude")
    else:
        plt.text(0.5, 0.5, "No geolocation data", ha="center")
        plt.axis("off")
    plt.tight_layout()
    plt.savefig(world_path, dpi=150)
    plt.close()
    assets["world_map"] = world_path

    return assets


def generate_pdf_report(events_csv="events_extracted.csv", output_pdf="bruteforce_report.pdf"):
    """
    Generate a PDF report containing:
    - KPIs
    - Charts
    - List of flagged brute-force attempts
    - ML-anomalies summary
    """
    # Load events
    if not os.path.exists(events_csv):
        logger.info("Events CSV not found; extracting from sample logs.")
        df = extract()
    else:
        df = pd.read_csv(events_csv, parse_dates=["timestamp"])

    # Create alerts and anomalies
    alerts = detect_bruteforce(df)
    anomalies = detect_anomalous_ips(df, window_minutes=120, contamination=0.1).reset_index()

    # Create chart assets
    assets = create_charts(df)

    # Build PDF
    c = canvas.Canvas(output_pdf, pagesize=landscape(A4))
    width, height = landscape(A4)
    margin = 40

    # Title
    c.setFont("Helvetica-Bold", 20)
    c.drawString(margin, height - margin, "Windows Log Brute-Force Detection Report")

    # Date and summary KPIs
    c.setFont("Helvetica", 10)
    total_events = len(df)
    total_failures = len(df[df["event_type"] == "failed_login"])
    unique_ips = df["ip"].nunique()
    unique_users = df["username"].nunique()

    c.drawString(margin, height - margin - 30, f"Total events analyzed: {total_events}")
    c.drawString(margin, height - margin - 45, f"Total failed logins: {total_failures}")
    c.drawString(margin + 250, height - margin - 30, f"Unique IPs: {unique_ips}")
    c.drawString(margin + 250, height - margin - 45, f"Unique users: {unique_users}")

    # Insert histogram
    img = ImageReader(assets["hist_failures_by_ip"])
    c.drawImage(img, margin, height - margin - 320, width=400, height=200, preserveAspectRatio=True)

    # Insert timeseries
    img2 = ImageReader(assets["ts_failures"])
    c.drawImage(img2, margin + 420, height - margin - 320, width=400, height=200, preserveAspectRatio=True)

    # Insert world map
    img3 = ImageReader(assets["world_map"])
    c.drawImage(img3, margin, height - margin - 540, width=400, height=150, preserveAspectRatio=True)

    # Alerts table (first page)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin + 420, height - margin - 540, "Brute-force Alerts")
    table_data = [["Type", "Value", "First Seen", "Last Seen", "Count", "Sample IPs/Users"]]
    for _, row in alerts.iterrows():
        table_data.append([
            row["flag_type"],
            str(row["flag_value"]),
            str(row["first_seen"]),
            str(row["last_seen"]),
            str(row["count"]),
            f"IPs:{row.get('sample_ips', [])} Users:{row.get('sample_users', [])}"
        ])
    if len(table_data) == 1:
        table_data.append(["-", "-", "-", "-", "-", "No alerts detected"])

    table = Table(table_data, colWidths=[60, 120, 120, 120, 40, 160])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d3d3d3")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
    ]))
    table.wrapOn(c, width, height)
    table.drawOn(c, margin + 420, height - margin - 720)

    # New page: anomalies
    c.showPage()
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, height - margin, "Anomaly Detection Results (IsolationForest)")
    c.setFont("Helvetica", 10)
    if anomalies.empty:
        c.drawString(margin, height - margin - 20, "No anomaly results to display.")
    else:
        # Build table for anomalies (top anomalous rows)
        grid = [["IP", "total_failures", "distinct_user_count", "failures_per_min", "anomaly_score", "anomaly_flag"]]
        for _, r in anomalies.iterrows():
            grid.append([
                r["ip"],
                str(r.get("total_failures", "")),
                str(r.get("distinct_user_count", "")),
                f"{r.get('failures_per_min',''):.2f}" if r.get("failures_per_min", "") != "" else "",
                f"{r.get('anomaly_score',''):.4f}" if r.get("anomaly_score", "") != "" else "",
                str(r.get("anomaly_flag", ""))
            ])
        tbl = Table(grid, colWidths=[140, 90, 110, 90, 90, 80])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d3d3d3")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
        ]))
        tbl.wrapOn(c, width, height)
        tbl.drawOn(c, margin, height - margin - 220)

    c.save()
    logger.info(f"Report generated at {output_pdf}")
    return output_pdf


if __name__ == "__main__":
    pdf = generate_pdf_report()
    print(f"Generated PDF: {pdf}")