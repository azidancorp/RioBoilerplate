from __future__ import annotations

import rio
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_COMFORTABLE
from app.currency import get_currency_config

class PricingPlans(ResponsiveComponent):
    """
    Pricing page showcasing a whimsical array of plans for potential customers,
    now offering both Monthly and Yearly payment cycles (with a discount).
    """

    # We'll keep track of the selected billing cycle using a boolean
    is_yearly_billing: bool = False

    def _on_billing_cycle_change(self, event: rio.SwitchChangeEvent) -> None:
        """Handle billing cycle switch changes."""
        self.is_yearly_billing = event.is_on

    def build(self) -> rio.Component:
        """
        Build the PricingPage UI with toggling between monthly and yearly pricing.
        """
        # Define the prices depending on the current billing cycle:
        currency_config = get_currency_config()
        currency_plural = currency_config.name_plural
        sidekick_price = (
            f"290 {currency_plural} / year (2 months free)"
            if self.is_yearly_billing
            else f"29 {currency_plural} / month"
        )
        hero_price = (
            f"990 {currency_plural} / year (2 months free)"
            if self.is_yearly_billing
            else f"99 {currency_plural} / month"
        )
        supernova_price = (
            f"4,990 {currency_plural} / year (2 months free)"
            if self.is_yearly_billing
            else f"499 {currency_plural} / month"
        )

        # Build pricing cards
        sidekick_card = rio.Card(
            rio.Column(
                rio.Text(
                    "Sidekick Plan",
                    style="heading2",
                    margin_bottom=1,
                ),
                rio.Text(
                    "Ideal for small business heroes in training. "
                    "Includes a single synergy token, a pinch of paradigm-shift, "
                    "and unlimited pep talks via carrier pigeon.",
                    margin_bottom=1,
                    overflow="wrap",
                ),
                rio.Text(sidekick_price, margin_bottom=2),
                rio.Button(
                    "Conquer the Market",
                    shape="rounded",
                ),
                spacing=1,
                margin=2,
            ),
            margin=1,
        )

        hero_card = rio.Card(
            rio.Column(
                rio.Text(
                    "Hero Plan",
                    style="heading2",
                    margin_bottom=1,
                ),
                rio.Text(
                    "For the business champion who wants to step up. "
                    "Boasts advanced synergy tokens, mid-range disruption, "
                    "and 24/7 'just-in-time' hyper-support.",
                    margin_bottom=1,
                    overflow="wrap",
                ),
                rio.Text(hero_price, margin_bottom=2),
                rio.Button(
                    "Battle with Innovation",
                    shape="rounded",
                ),
                spacing=1,
                margin=2,
            ),
            margin=1,
        )

        supernova_card = rio.Card(
            rio.Column(
                rio.Text(
                    "Supernova Plan",
                    style="heading2",
                    margin_bottom=1,
                ),
                rio.Text(
                    "Unleash the pinnacle of synergy with enterprise-grade "
                    "buzzword potential, multi-dimensional disruption, "
                    "and an infinite supply of ninja-level solutions.",
                    margin_bottom=1,
                    overflow="wrap",
                ),
                rio.Text(supernova_price, margin_bottom=2),
                rio.Button(
                    "Launch into Orbit",
                    shape="rounded",
                ),
                spacing=1,
                margin=2,
            ),
            margin=1,
        )

        return CenterComponent(
            rio.Column(
                # Heading
                rio.Text(
                    "Pricing Plans",
                    style="heading1",
                    margin_bottom=2,
                    align_x=0.5,
                ),

                # Switch for Monthly/Yearly billing
                rio.Row(
                    rio.Text("Monthly"),
                    rio.Switch(
                        is_on=self.is_yearly_billing,
                        on_change=self._on_billing_cycle_change,
                        margin_x=1,
                    ),
                    rio.Text("Yearly (2 months free!)"),
                    margin_bottom=3,
                    align_x=0.5,
                ),

                # Use FlowContainer for pricing cards - auto-wraps on mobile
                rio.FlowContainer(
                    sidekick_card,
                    hero_card,
                    supernova_card,
                    row_spacing=2,
                    column_spacing=2,
                    justify="center",
                ),
            ),
            width_percent=100,
            margin_top=5,
        )


@rio.page(
    name="Pricing",
    url_segment="pricing",
)
class PricingPage(rio.Component):
    """
    Pricing page showcasing a whimsical array of plans for potential customers,
    now offering both Monthly and Yearly payment cycles (with a discount).
    """

    def build(self) -> rio.Component:
        """
        Build the PricingPage UI with toggling between monthly and yearly pricing.
        """
        return CenterComponent(
            PricingPlans(),
            width_percent=WIDTH_COMFORTABLE,
            margin_top=5,
        )
