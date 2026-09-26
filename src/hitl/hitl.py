"""
Lab 11 — Optional enrichment: Human-in-the-Loop Design
  (Không chấm — tham khảo. Tóm tắt nộp do scripts/grade.py tự sinh,
   không viết report/*.md tay.)
  - Confidence Router
  - 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# Optional enrichment: ConfidenceRouter (không chấm)
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# Optional enrichment: 3 HITL decision points
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-Value Money Transfer Authorization",
        "trigger": "Customer initiates a fund transfer exceeding 50,000,000 VND or unusual beneficiary destination",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Source account, destination account, transfer amount, device fingerprint, OTP verification status",
        "example": "Customer requests transfer of 100,000,000 VND to a newly added overseas beneficiary account",
        "approval_path": "Approve executes API transfer; Reject halts transfer and notifies user; Timeout holds transaction for 15 mins then auto-cancels",
        "audit_fields": "correlation_id, user_id, source_acc, dest_acc, amount, risk_score, reviewer_id, reviewer_decision, timestamp",
    },
    {
        "id": 2,
        "name": "Security Credentials & Contact Information Update",
        "trigger": "Request to change registered phone number, email address, or reset online banking password",
        "hitl_model": "human-on-the-loop",
        "context_needed": "National ID photo, biometric match score, previous and new phone/email, account transaction history",
        "example": "User requests password reset and changes registered phone number from an unrecognized IP address",
        "approval_path": "Approve applies credentials update; Reject locks account for security review; Timeout triggers callback verification",
        "audit_fields": "correlation_id, user_id, field_changed, old_value, new_value, biometric_confidence, agent_id, decision_timestamp",
    },
    {
        "id": 3,
        "name": "Account Termination and Irreversible Data Deletion",
        "trigger": "Customer requests full closure of bank account or GDPR/privacy data purge",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Account outstanding balance, active loans or credit cards, pending transactions, identity verification documents",
        "example": "Customer requests to close checking account with remaining balance of 2,500,000 VND and pending credit card charge",
        "approval_path": "Approve initiates balance refund and closes account; Reject notifies unsettled obligations; Timeout alerts branch manager",
        "audit_fields": "correlation_id, user_id, account_id, final_balance, pending_settlement_ids, officer_signature, audit_timestamp",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
