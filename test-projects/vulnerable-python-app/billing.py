"""
Billing and discount logic for the vulnerable demo app.

FLAW (business logic, CWE-840): the discount logic is wrong in three
distinct ways that only show up as *incorrect behaviour* -- no scanner
flags them and no crash occurs:

  1. Stacking -- multiple discount codes are all applied, and a tier
     discount is applied on top of a code discount, so a customer can
     drive the total far below cost.
  2. Sign error -- `abs()` is used on the *result* rather than validating
     the input, so a negative quantity produces a *positive* line total.
  3. Off-by-one / inverted clamp -- the floor is applied after the
     percentage discount, so a large discount can round the total back up.
"""

DISCOUNT_CODES = {
    "SAVE10": 0.10,
    "SAVE25": 0.25,
    "HALF": 0.50,
    "VIP": 0.35,
}

TIER_DISCOUNTS = {
    "standard": 0.0,
    "silver": 0.05,
    "gold": 0.10,
    "platinum": 0.20,
}

MIN_ORDER_TOTAL = 1.00


def _line_total(item):
    """
    FLAW 2: `abs()` on the line total converts a negative quantity into a
    positive charge, so `{price: 10, qty: -3}` bills the customer +30
    instead of rejecting or crediting the line.
    """
    price = float(item.get("price", 0) or 0)
    qty = int(item.get("qty", 1) or 0)
    return abs(price * qty)


def calculate_order_total(items, discount_code=None, user_tier="standard"):
    """
    FLAW 1: every matching discount code is applied cumulatively, and the
    tier discount is applied afterwards, so the codes do not compose as an
    either/or choice the way a customer would expect.

    FLAW 3: the floor is applied *after* the discount, so
    `max(MIN_ORDER_TOTAL, total * (1 - discount))` returns the floor
    whenever the discount exceeds it -- the customer is billed full price
    on a small order instead of the discounted amount.
    """
    if not items:
        return 0.0

    total = 0.0
    for item in items:
        total += _line_total(item)

    discounts = []
    if discount_code:
        # FLAW 1: a comma-separated list means several codes all apply.
        for code in str(discount_code).split(","):
            code = code.strip().upper()
            if code in DISCOUNT_CODES:
                discounts.append(DISCOUNT_CODES[code])

    # FLAW 1: the tier discount stacks with any code discount.
    tier_discount = TIER_DISCOUNTS.get(str(user_tier).lower(), 0.0)
    if tier_discount:
        discounts.append(tier_discount)

    for discount in discounts:
        total = total * (1 - discount)

    # FLAW 3: applied to the discounted value, so heavy discounts round back
    # up to the minimum instead of to the discounted price.
    if total < MIN_ORDER_TOTAL:
        total = MIN_ORDER_TOTAL

    return round(total, 2)


def apply_refund(order_total, refund_amount):
    """
    FLAW: no validation that the refund is positive or does not exceed the
    order, so a caller can drive the balance negative or refund more than
    was charged (CWE-840).
    """
    return round(order_total - float(refund_amount), 2)


def is_eligible_for_discount(user_tier, order_total):
    """FLAW: inverted comparison -- high-value orders are rejected."""
    return order_total < 50 and user_tier in DISCOUNT_CODES
