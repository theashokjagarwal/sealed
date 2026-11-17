import unittest
import decimal
from src.order_service import Order, OrderItem, process_order_status

class TestOrderService(unittest.TestCase):
    def test_total_calculation(self):
        items = [
            OrderItem(sku="SKU-001", quantity=2, unit_price=decimal.Decimal("10.00")),
            OrderItem(sku="SKU-002", quantity=1, unit_price=decimal.Decimal("50.00")),
        ]
        order = Order(order_id="ORD-1001", customer_id="CUST-42", items=items)
        self.assertEqual(order.subtotal(), decimal.Decimal("70.00"))
        self.assertEqual(order.tax(), decimal.Decimal("5.78"))
        self.assertEqual(order.total(), decimal.Decimal("75.78"))

    def test_fulfillment_status(self):
        order = Order(order_id="ORD-1002", customer_id="CUST-43", items=[
            OrderItem(sku="SKU-001", quantity=1, unit_price=decimal.Decimal("10.00"))
        ])
        self.assertEqual(process_order_status(order, payment_confirmed=False), "PAYMENT_PENDING")
        self.assertEqual(process_order_status(order, payment_confirmed=True), "QUEUED_FOR_FULFILLMENT")

if __name__ == "__main__":
    unittest.main()
