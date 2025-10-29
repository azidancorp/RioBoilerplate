from __future__ import annotations

from dataclasses import KW_ONLY, field
from datetime import datetime, timezone

import rio
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from app.components.testimonial import Testimonial
from app.components.dashboard_components import DeltaCard
from app.components.currency_summary import CurrencySummary, CurrencyOverview as CurrencySnapshot
from app.persistence import Persistence
from app.data_models import UserSession

# -----------------------------
# Component Definitions
# -----------------------------

class Overview(rio.Component):

    currency_overview: CurrencySnapshot | None = None

    @rio.event.on_populate
    async def on_populate(self):
        try:
            user_session = self.session[UserSession]
            persistence = self.session[Persistence]
        except KeyError:
            self.currency_overview = None
            return

        overview_data = await persistence.get_currency_overview(user_session.user_id)
        updated_at = overview_data.get("updated_at")
        if isinstance(updated_at, datetime):
            updated = updated_at
        elif updated_at is None:
            updated = None
        else:
            updated = datetime.fromtimestamp(updated_at, tz=timezone.utc)

        self.currency_overview = CurrencySnapshot(
            balance_minor=overview_data["balance_minor"],
            updated_at=updated,
        )

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

                self.currency_overview and CurrencySummary(
                    overview=self.currency_overview,
                    title="Primary Balance",
                ) or rio.Card(
                    rio.Text("Balance data unavailable", style="dim"),
                    color="hud",
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


class ProductionReport(rio.Component):
    def build(self):

        # Create a DataFrame for crop harvest sources and amounts
        harvest_sources = {
            'Crop_Type': ['Apples', 'Pears', 'Cherries'],
            'Harvest_kg': [5_000, 2_000, 1_000]
        }
        harvest_df = pd.DataFrame(harvest_sources)

        # Pie chart for harvest breakdown
        harvest_chart = px.pie(
            harvest_df,
            names='Crop_Type',
            values='Harvest_kg',
            title='Harvest Breakdown',
            hole=0,
            labels={'Crop_Type': 'Crop', 'Harvest_kg': 'Kilograms'}
        )
        harvest_chart.update_traces(textposition='inside', textinfo='percent+label')
        harvest_chart.update_layout(
            showlegend=True,
            uniformtext_minsize=12,
            uniformtext_mode='hide',
            template='plotly_dark'
        )

        # Generate dummy monthly data for harvest and costs
        num_months = 12
        months = pd.date_range(start='2023-01-01', periods=num_months, freq='ME').strftime('%b %Y')

        np.random.seed(42)
        monthly_harvest = np.random.randint(4_000, 10_000, num_months)
        monthly_costs = np.random.randint(3_000, 8_000, num_months)

        performance_data = pd.DataFrame({
            'Month': months,
            'Harvest_kg': monthly_harvest,
            'Costs_GBP': monthly_costs,
            'Net_Yield_kg': monthly_harvest - monthly_costs
        })

        # Bar and line chart for monthly harvest and costs
        production_chart = go.Figure()
        production_chart.add_trace(go.Bar(
            x=performance_data['Month'],
            y=performance_data['Harvest_kg'],
            name='Harvest',
            marker_color='rgb(39, 174, 96)',
            offsetgroup=0
        ))

        production_chart.add_trace(go.Bar(
            x=performance_data['Month'],
            y=-performance_data['Costs_GBP'],
            name='Costs',
            marker_color='rgb(231, 76, 60)',
            offsetgroup=0
        ))

        production_chart.add_trace(go.Scatter(
            x=performance_data['Month'],
            y=performance_data['Net_Yield_kg'],
            name='Net Yield',
            line=dict(color='rgb(52, 152, 219)', width=2)
        ))

        production_chart.update_layout(
            title='Monthly Harvest and Costs (2023)',
            xaxis_title='Month',
            yaxis_title='Amount',
            barmode='relative',
            height=600,
            template='plotly_dark'
        )

        production_chart.add_shape(
            type='line',
            x0=0,
            y0=0,
            x1=1,
            y1=0,
            xref='paper',
            yref='y',
            line=dict(color='black', width=2)
        )

        production_chart.update_yaxes(
            title_font=dict(size=14),
            title_standoff=25
        )
        production_chart.update_xaxes(tickangle=-45)

        # Production Report Text
        production_report = """
HARVEST PERFORMANCE REPORT - 2023

**HEADLINE FIGURES**
- **Total Annual Harvest:** ~8,000 kg
- **Average Monthly Harvest:** ~6,500 kg
- **Peak Harvest Month:** May 2023 (9,500 kg)
- **Lowest Harvest Month:** March 2023 (4,100 kg)

**CROP MIX**
- **Apples:** 62.5% (Primary crop)
- **Pears:** 25.0%
- **Cherries:** 12.5%

**KEY HIGHLIGHTS**
- Positive net yield maintained for 8 out of 12 months
- Strong performance in Q2 (Apr-Jun) with consistent harvest above 7,000 kg
- Costs stabilized in H2, averaging £5,000 monthly
- Year ended with increasing yields in December

**[Detailed Monthly Analysis]**
- Q1 showed variability with lower harvest volumes
- Q2 demonstrated strongest output with a peak in May
- Q3 remained steady despite rising costs
- Q4 indicated resilience and stable yields despite challenging conditions

**[Risk Analysis]**
- High dependency on a single crop type (Apples)
- Occasional costs surpassing harvest value
- Seasonal fluctuations suggest need for improved storage and planning
- Diversification needed to reduce reliance on one primary crop
        """

        return rio.Column(
            rio.Text("Production Report", style="heading3"),
            # First Row with DeltaCards
            rio.Row(
                DeltaCard(
                    title="Total Harvest",
                    value="8,000 kg",
                    color=rio.Color.from_hex('#2980B9'),
                    delta_a=500,
                    delta_b=200,
                ),
                DeltaCard(
                    title="Storage Capacity",
                    value="20,000 kg",
                    color=rio.Color.from_hex('#8E44AD'),
                    delta_a=1_000,
                    delta_b=300,
                ),
                DeltaCard(
                    title="Sales",
                    value="£120,000",
                    color=rio.Color.from_hex('#27AE60'),
                    delta_a=2_000,
                    delta_b=500,
                ),
                DeltaCard(
                    title="Costs",
                    value="£50,000",
                    color=rio.Color.from_hex('#E67E22'),
                    delta_a=1_000,
                    delta_b=250,
                ),
                DeltaCard(
                    title="Profit",
                    value="£70,000",
                    color=rio.Color.from_hex('#C0392B'),
                    delta_a=1_500,
                    delta_b=400,
                ),
                spacing=2,
            ),
            # Second Row with Plots
            rio.Row(
                rio.Plot(production_chart, min_height=30),
                rio.Plot(harvest_chart, min_height=30),
                proportions=[2, 1],
                spacing=2
            ),
            rio.Row(
                rio.Revealer(
                    header="Production Report - Click to reveal",
                    header_style="heading3",
                    # content=rio.Text(production_report, overflow="wrap"),
                    content=rio.Markdown(production_report),
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
            ProductionReport(),
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
