"""
Order Fulfillment & Billing Service
Standard deterministic backend service. Zero AI / LLM dependencies.
"""

from dataclasses import dataclass
from typing import List, Optional
import decimal

@dataclass
class OrderItem:
    sku: str
    quantity: int
    unit_price: decimal.Decimal

@dataclass
class Order:
    order_id: str
    customer_id: str
    items: List[OrderItem]
    tax_rate: decimal.Decimal = decimal.Decimal("0.0825")

    def subtotal(self) -> decimal.Decimal:
        return sum((item.unit_price * item.quantity for item in self.items), decimal.Decimal("0.00"))

    def tax(self) -> decimal.Decimal:
        return (self.subtotal() * self.tax_rate).quantize(decimal.Decimal("0.01"))

    def total(self) -> decimal.Decimal:
        return self.subtotal() + self.tax()

def process_order_status(order: Order, payment_confirmed: bool) -> str:
    if not payment_confirmed:
        return "PAYMENT_PENDING"
    if not order.items:
        return "EMPTY_ORDER_REJECTED"
    return "QUEUED_FOR_FULFILLMENT"
