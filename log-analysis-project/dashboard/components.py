"""
Reusable UI components for the Dash dashboard.

Contains:
- kpi_card: function to create simple KPI card
"""

import dash_html_components as html
import dash_core_components as dcc


def kpi_card(title, value, subtitle=""):
    """
    Return a small card layout showing a KPI.
    """
    return html.Div(
        className="kpi-card",
        children=[
            html.Div(title, className="kpi-title", style={"fontSize": "12px", "color": "#666"}),
            html.Div(value, className="kpi-value", style={"fontSize": "22px", "fontWeight": "bold"}),
            html.Div(subtitle, className="kpi-sub", style={"fontSize": "10px", "color": "#999"}),
        ],
        style={
            "border": "1px solid #e1e1e1",
            "padding": "10px",
            "borderRadius": "4px",
            "backgroundColor": "#fff",
            "width": "100%",
            "boxShadow": "0 1px 2px rgba(0,0,0,0.05)",
        }
    )