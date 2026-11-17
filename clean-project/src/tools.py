"""
TitanGate Secure Tool Handlers
All operations are read-only and strictly sandboxed.
"""

def lookup_faq(topic: str) -> str:
    """Safely retrieves pre-approved FAQ answers."""
    topic_clean = topic.strip().lower()
    allowed_topics = {
        "shipping": "Standard delivery window is 3-5 days.",
        "returns": "Items returnable within 30 days."
    }
    return allowed_topics.get(topic_clean, "Topic not found.")
