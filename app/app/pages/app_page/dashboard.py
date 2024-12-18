from __future__ import annotations

from dataclasses import KW_ONLY, field
from typing import *  # type: ignore

import rio
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Circle

from app.components.testimonial import Testimonial
from app.components.dashboard_components import DeltaCard

# -----------------------------
# Component Definitions
# -----------------------------

class Overview(rio.Component):

    def build(self):

        return rio.Column(

            rio.Text("Executive Dashboard", style="heading3"),

            rio.Row(

                DeltaCard(
                    title="Strategic Plan Execution Velocity",
                    value="68%",
                    delta_a=12,
                    delta_b=8,
                    color=rio.Color.from_hex('#2ECC71')
                ),

                DeltaCard(
                    title="Critical Risk Incidents",
                    value="7",
                    delta_a=-2,
                    delta_b=-1,
                    color=rio.Color.from_hex('#E74C3C')
                ),

                DeltaCard(
                    title="Customer Experience Feedback",
                    value="42",
                    delta_a=-5,
                    delta_b=-3,
                    color=rio.Color.from_hex('#F39C12')
                ),

                DeltaCard(
                    title="Project Milestone Achievement Rate",
                    value="82%",
                    delta_a=7,
                    delta_b=5,
                    color=rio.Color.from_hex('#9B59B6')
                ),

                DeltaCard(
                    title="Regulatory Compliance Performance",
                    value="95%",
                    delta_a=2,
                    delta_b=1,
                    color=rio.Color.from_hex('#1ABC9C')
                ),

                spacing=2,

            ),
            spacing=3
        )

class SalesDashboard(rio.Component):

    def build(self):

        # Load the pre-generated data
        sales_data = pd.read_csv('app/data/sales_data.csv', parse_dates=['Week'])

        # Extract columns
        weeks = sales_data['Week']
        online_sales = sales_data['Online Sales']
        in_store_sales = sales_data['In-Store Sales']
        total_sales = sales_data['Total Sales']

        # Create a DataFrame to hold sales data
        sales_data = pd.DataFrame({
            'Week': weeks,
            'Online Sales': online_sales,
            'In-Store Sales': in_store_sales,
            'Total Sales': total_sales
        })

        # Create the Sales Performance Chart
        sales_chart = go.Figure()

        # Add In-Store Sales trace
        sales_chart.add_trace(go.Scatter(
            x=sales_data['Week'],
            y=sales_data['In-Store Sales'],
            mode='lines',
            name='In-Store Sales',
            fill='tonexty',
            line=dict(color='rgba(255, 140, 0, 0.6)')  # Orange color with transparency
        ))

        # Add Online Sales trace
        sales_chart.add_trace(go.Scatter(
            x=sales_data['Week'],
            y=sales_data['Total Sales'],
            mode='lines',
            name='Online Sales',
            fill='tonexty',
            line=dict(color='rgba(30, 144, 255, 0.6)')  # Dodger Blue with transparency
        ))

        # Update layout for the sales chart
        sales_chart.update_layout(
            title='Sales Performance Over Time',
            xaxis_title='Week',
            yaxis_title='Number of Units Sold',
            yaxis=dict(rangemode='tozero'),
            legend_title='Sales Channel',
            height=400,
            template='plotly_dark'
        )

        # Generate future dates for a 10-year sales forecast
        today = pd.Timestamp.now()
        future_dates = pd.date_range(start=today, periods=365*10, freq='D')

        # Base sales value from the last week of current data
        base_sales = sales_data['Total Sales'].iloc[-1]
        
        # Create a linear forecast for future sales (e.g., 5% annual growth)
        days = len(future_dates)
        growth_rate = 0.05  # 5% growth over 10 years
        future_sales = base_sales * (1 + growth_rate) ** (np.arange(days) / 365)
        
        # Calculate upper and lower bounds for the forecast (±10%)
        future_sales_lower = future_sales * 0.9
        future_sales_upper = future_sales * 1.1

        # Create the Sales Forecast Chart
        forecast_chart = go.Figure()

        # Add Forecasted Sales trace
        forecast_chart.add_trace(go.Scatter(
            x=future_dates,
            y=future_sales,
            mode='lines',
            name='Forecasted Sales',
            line=dict(dash='dash', color='lime')
        ))

        # Add Upper Bound trace
        forecast_chart.add_trace(go.Scatter(
            x=future_dates,
            y=future_sales_upper,
            mode='lines',
            line=dict(width=0),
            showlegend=False
        ))

        # Add Lower Bound trace with fill between upper and lower bounds
        forecast_chart.add_trace(go.Scatter(
            x=future_dates,
            y=future_sales_lower,
            mode='lines',
            line=dict(width=0),
            fill='tonexty',
            fillcolor='rgba(68, 68, 68, 0.3)',  # Semi-transparent gray
            name='Forecast Range'
        ))

        # Update layout for the forecast chart
        forecast_chart.update_layout(
            title='10-Year Sales Forecast',
            xaxis_title='Date',
            yaxis_title='Projected Sales ($)',
            yaxis=dict(rangemode='tozero'),
            height=400,
            template='plotly_dark'
        )

        # Optionally, create additional charts such as Revenue vs. Expenses
        # For brevity, we'll stick to two primary charts here

        # Assemble the dashboard layout
        return rio.Column(
            rio.Text("Sales Dashboard", style="heading3"),
            rio.Row(
                rio.Plot(sales_chart, min_height=30),
                rio.Plot(forecast_chart, min_height=30),
                spacing=2,
            ),
            spacing=2
        )


class FinanceReport(rio.Component):
    def build(self):
        # Create a DataFrame for funding sources and amounts
        funding_sources = {
            'Funding_Source': ['Equity Raise', 'Rental Income', 'Arrangement Fees'],
            'Amount_GBP': [500_000, 200_000, 100_000]
        }
        funding_df = pd.DataFrame(funding_sources)

        # Pie chart for income/funding breakdown
        income_funds_chart = px.pie(
            funding_df,
            names='Funding_Source',
            values='Amount_GBP',
            title='Income/Funds Raised Breakdown',
            hole=0,
            labels={'Funding_Source': 'Source', 'Amount_GBP': 'Amount (£)'}
        )
        income_funds_chart.update_traces(textposition='inside', textinfo='percent+label')
        income_funds_chart.update_layout(
            showlegend=True,
            uniformtext_minsize=12,
            uniformtext_mode='hide',
            template='plotly_dark'
        )

        # Generate financial data for income and burn rate
        num_months = 12
        months = pd.date_range(start='2023-01-01', periods=num_months, freq='ME').strftime('%b %Y')

        np.random.seed(42)
        monthly_income = np.random.randint(40_000, 100_000, num_months)
        monthly_burn_rate = np.random.randint(30_000, 80_000, num_months)

        financial_data = pd.DataFrame({
            'Month': months,
            'Income_GBP': monthly_income,
            'Burn_Rate_GBP': monthly_burn_rate,
            'Net_Balance_GBP': monthly_income - monthly_burn_rate
        })

        # Bar and line chart for income, burn rate, and net balance
        income_expenditure_chart = go.Figure()
        income_expenditure_chart.add_trace(go.Bar(
            x=financial_data['Month'],
            y=financial_data['Income_GBP'],
            name='Income',
            marker_color='rgb(39, 174, 96)',
            offsetgroup=0
        ))

        income_expenditure_chart.add_trace(go.Bar(
            x=financial_data['Month'],
            y=-financial_data['Burn_Rate_GBP'],
            name='Burn Rate',
            marker_color='rgb(231, 76, 60)',
            offsetgroup=0
        ))

        income_expenditure_chart.add_trace(go.Scatter(
            x=financial_data['Month'],
            y=financial_data['Net_Balance_GBP'],
            name='Net Balance',
            line=dict(color='rgb(52, 152, 219)', width=2)
        ))

        income_expenditure_chart.update_layout(
            title='Monthly Income and Burn Rate (2023)',
            xaxis_title='Month',
            yaxis_title='Amount (£)',
            barmode='relative',
            height=600,
            template='plotly_dark'
        )

        income_expenditure_chart.add_shape(
            type='line',
            x0=0,
            y0=0,
            x1=1,
            y1=0,
            xref='paper',
            yref='y',
            line=dict(color='black', width=2)
        )

        income_expenditure_chart.update_yaxes(
            tickprefix="£",
            title_font=dict(size=14),
            title_standoff=25
        )
        income_expenditure_chart.update_xaxes(tickangle=-45)

        # Finance Report Text
        finance_report = """
FINANCIAL PERFORMANCE REPORT - 2023

**HEADLINE FIGURES**
- **Total Annual Income:** ~£750,000
- **Average Monthly Income:** £62,500
- **Peak Revenue Month:** May 2023 (£85,000)
- **Lowest Revenue Month:** March 2023 (£40,000)

**FUNDING STRUCTURE**
- **Equity Raise:** 62.5% (Primary funding source)
- **Rental Income:** 25.0%
- **Arrangement Fees:** 12.5%

**KEY HIGHLIGHTS**
- Positive net balance maintained for 8 out of 12 months
- Strong performance in Q2 (Apr-Jun) with consistent income above £70,000
- Burn rate stabilized in H2, averaging £45,000 monthly
- Year ended with positive trajectory in December

**[Detailed Monthly Analysis]**
- Q1 showed volatility with declining revenues
- Q2 demonstrated strongest performance with peak in May
- Q3 maintained steady performance despite increased burn rate
- Q4 showed resilient income despite market conditions

**[Risk Analysis]**
- High dependency on equity funding (62.5%)
- Burn rate occasionally exceeding monthly income
- Seasonal revenue patterns suggest need for cash reserve management
- Diversification needed to reduce reliance on equity funding
        """

        return rio.Column(
            rio.Text("Finance Report", style="heading3"),
            # First Row with DeltaCards
            rio.Row(
                DeltaCard(
                    title="Total Funding",
                    value="£5,000,000",
                    color=rio.Color.from_hex('#2980B9'),
                    delta_a=50_000,
                    delta_b=20_000,
                ),
                DeltaCard(
                    title="Financing",
                    value="£2,000,000",
                    color=rio.Color.from_hex('#8E44AD'),
                    delta_a=15_000,
                    delta_b=5_000,
                ),
                DeltaCard(
                    title="Income",
                    value="£1,200,000",
                    color=rio.Color.from_hex('#27AE60'),
                    delta_a=12_000,
                    delta_b=3_000,
                ),
                DeltaCard(
                    title="Burn Rate",
                    value="£50,000/month",
                    color=rio.Color.from_hex('#E67E22'),
                    delta_a=5_000,
                    delta_b=1_000,
                ),
                DeltaCard(
                    title="Outgoings",
                    value="£1,000,000",
                    color=rio.Color.from_hex('#C0392B'),
                    delta_a=8_000,
                    delta_b=2_000,
                ),
                spacing=2,
            ),
            # Second Row with Plots
            rio.Row(
                rio.Plot(income_expenditure_chart, min_height=30),
                rio.Plot(income_funds_chart, min_height=30),
                proportions=[2, 1],
                spacing=2
            ),
            rio.Row(
                rio.Revealer(
                    header="Finance Report - Click to reveal",
                    header_style="heading3",
                    content=rio.Text(finance_report, overflow="wrap"),
                ),
            ),
            spacing=2
        )



class Board(rio.Component):
    """
    Executive Board Dashboard with various reports and metrics.
    """
    def build(self) -> rio.Component:
        return rio.Column(
            # Header Section
            rio.Text("Mission Intelligence", style="heading2"),

            # Integrated Sections
            Overview(),
            SalesDashboard(),
            FinanceReport(),


            # General Styling
            spacing=4,
            margin=2,
            grow_x=True,
            align_y=0,
        )

# -----------------------------
# Main Dashboard Class
# -----------------------------

@rio.page(
    name="Dashboard",
    url_segment="dashboard",
)
class Dashboard(rio.Component):
    """
    A comprehensive executive dashboard integrating various organizational metrics and reports.
    """
    def build(self) -> rio.Component:

        return rio.Column(

            # Main Board Dashboard
            Board(),

            # General Styling
            spacing=4,
            margin=2,
            grow_x=True,
            align_y=0,
        )
