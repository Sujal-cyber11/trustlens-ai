"""Pytest suite verifying 16 deterministic heuristic and PII scrubbing test cases."""
from __future__ import annotations

from heuristics import evaluate_heuristics, scrub_pii


def test_01_homoglyph_arnazon() -> None:
    res = evaluate_heuristics("arnazon.com")
    assert res["base_score"] >= 90
    assert res["impersonation_detected"] is True


def test_02_homoglyph_g00gle() -> None:
    res = evaluate_heuristics("https://g00gle.com/login")
    assert res["base_score"] >= 90
    assert res["impersonation_detected"] is True


def test_03_typosquat_hdfcbnk() -> None:
    res = evaluate_heuristics("http://hdfcbnk.com/netbanking")
    assert res["base_score"] >= 90
    assert res["impersonation_detected"] is True


def test_04_impersonating_ai_chatgpi() -> None:
    res = evaluate_heuristics("https://chatgpi-pro.com/login")
    assert res["base_score"] >= 90
    assert res["impersonation_detected"] is True


def test_05_vague_attention_bait() -> None:
    res = evaluate_heuristics("5M credited to your account, click here")
    assert res["base_score"] >= 80
    assert "Vague" in res["detected_category"]


def test_06_linkless_credential_harvesting() -> None:
    text = "SECURITY ALERT: Your bank account is temporarily restricted. Reply with your internet banking username, password, and OTP to reactivate it."
    res = evaluate_heuristics(text)
    assert res["base_score"] >= 95


def test_07_upi_collect_trap() -> None:
    text = "Ramesh (OLX Buyer) has requested Rs. 4,500. Note: 'Cashback/Refund for Sofa'. Tap 'Pay ₹4,500' and enter your UPI PIN to receive money."
    res = evaluate_heuristics(text)
    assert res["base_score"] >= 90
    assert "Collect" in res["detected_category"]


def test_08_genuine_sbi_otp_is_low() -> None:
    text = "482910 is your One Time Password (OTP) for netbanking login at SBI. Do NOT share this OTP with anyone. Bank employees never ask for OTP."
    res = evaluate_heuristics(text)
    assert res["base_score"] <= 10
    assert res["is_verified_safe"] is True
    assert res["pass1_naive_score"] >= 35  # Proves Pass-1 flags it while Pass-2 clears it


def test_09_genuine_upi_receipt_is_low() -> None:
    text = "Paid Rs 120 to Mother Dairy via UPI Ref No 628194021842. Thank you for using BHIM UPI."
    res = evaluate_heuristics(text)
    assert res["base_score"] == 0
    assert res["is_verified_safe"] is True


def test_10_legit_chatgpt_domain_is_low() -> None:
    res = evaluate_heuristics("https://chatgpt.com")
    assert res["base_score"] == 0
    assert res["whitelisted"] is True


def test_11_ussd_call_forwarding_trap() -> None:
    text = "Courier agent: Sir your parcel is being returned. Dial *401*9876543210# to cancel return."
    res = evaluate_heuristics(text)
    assert res["base_score"] >= 95


def test_12_emotional_emergency_scam() -> None:
    text = "Dad, my phone fell and broke, mother met with accident and is in hospital, urgently send money Rs 15000 via UPI to this friend's number."
    res = evaluate_heuristics(text)
    assert res["base_score"] >= 85


def test_13_empty_string_edge_case() -> None:
    res = evaluate_heuristics("   ")
    assert res["base_score"] == 0
    assert res["has_url"] is False


def test_14_twenty_thousand_chars_edge_case() -> None:
    long_text = "Normal benign text block. " * 1000
    res = evaluate_heuristics(long_text)
    assert 0 <= res["base_score"] <= 100


def test_15_emoji_and_mixed_script_homograph() -> None:
    # 'аmazon.com' using Cyrillic small letter 'а' (\u0430)
    res = evaluate_heuristics("🎁 Claim prize at https://\u0430mazon.com/win")
    assert res["base_score"] >= 85


def test_16_pii_scrubber_redacts_sensitive_tokens() -> None:
    raw = "Call 9811223344 or email user@test.com. OTP is 482910. Card 4111 2222 3333 4444."
    scrubbed = scrub_pii(raw)
    assert "9811223344" not in scrubbed
    assert "user@test.com" not in scrubbed
    assert "482910" not in scrubbed
    assert "4111 2222 3333 4444" not in scrubbed
