"""Comprehensive pytest suite verifying BUG 1 (401/403 token auth), BUG 2 (scoring & zero-signal behaviour),
and BUG 3 (feedback idempotency, domain validation, user_allowlist, and self-scan marker skipping).

No test depends on network access.
"""
from __future__ import annotations

import copy
import pytest
from fastapi.testclient import TestClient

import ai_auditor
from ai_auditor import (
    BASE_WEIGHTS,
    DEFAULT_MEMORY,
    apply_user_feedback,
    load_memory,
    migrate_and_clean_memory_on_startup,
    save_memory,
)
from collectors import get_extension_token, should_skip_collected_text
from heuristics import TRUSTLENS_INTERNAL_MARKER
from main import app
from page_analysis import PageAuditRequest, PageSignal, evaluate_page_signals

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_memory(tmp_path, monkeypatch):
    """Isolates agent_memory.json per test so tests never pollute real state or require network."""
    test_mem_file = tmp_path / "test_agent_memory.json"
    monkeypatch.setattr(ai_auditor, "MEMORY_FILE", str(test_mem_file))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    save_memory(copy.deepcopy(DEFAULT_MEMORY))
    yield


# --------------------------------------------------------------------------- #
# BUG 1 & BUG 2 REQUIRED PYTEST CASES
# --------------------------------------------------------------------------- #
def test_01_github_login_zero_signals_is_low() -> None:
    req = PageAuditRequest(
        url="https://github.com/login",
        hostname="github.com",
        title="Sign in to GitHub · GitHub",
        signals=[],
        text_sample="Sign in to GitHub. Username or email address. Password. Forgot password?",
    )
    res = evaluate_page_signals(req, load_memory())
    assert res["overall_risk_score"] == "Low"
    assert res["base_score"] <= 20
    assert res["is_suspicious"] is False


def test_02_college_portal_student_login_zero_signals_is_low() -> None:
    req = PageAuditRequest(
        url="https://portal.mycollege.ac.in/login",
        hostname="portal.mycollege.ac.in",
        title="Student Portal Login",
        signals=[],
        text_sample="Student Login, enter roll number and password",
    )
    res = evaluate_page_signals(req, load_memory())
    assert res["overall_risk_score"] == "Low"
    assert res["base_score"] <= 20
    assert res["is_suspicious"] is False


def test_03_unknown_domain_enter_password_zero_signals_is_at_most_medium_and_needs_ai() -> None:
    req = PageAuditRequest(
        url="https://fake-bank.example/login",
        hostname="fake-bank.example",
        title="Login",
        signals=[],
        text_sample="Enter your password",
    )
    res = evaluate_page_signals(req, load_memory())
    assert res["overall_risk_score"] in ("Low", "Medium")
    assert res["base_score"] <= 45
    assert res["needs_ai"] is True
    # Zero signals must never fabricate countdown, checkbox, Win+R, or support number text
    combined_expl = f"{res['calm_message']} {res['how_it_affects_user']} {' '.join(res['recommended_actions'])}".lower()
    assert "countdown" not in combined_expl
    assert "checkbox" not in combined_expl
    assert "win+r" not in combined_expl


def test_04_cross_domain_password_form_action_is_high() -> None:
    req = PageAuditRequest(
        url="https://fake-bank.example/login",
        hostname="fake-bank.example",
        title="Login",
        signals=[
            PageSignal(
                id="cross_domain_password_form",
                severity="High",
                evidence="Form on 'fake-bank.example' submits to 'collector-evil.org'",
                count=1,
            )
        ],
        text_sample="Enter your password",
    )
    res = evaluate_page_signals(req, load_memory())
    assert res["overall_risk_score"] == "High"
    assert res["base_score"] >= 90


def test_05_arnazon_homoglyph_with_password_field_is_high() -> None:
    req = PageAuditRequest(
        url="https://arnazon.com/ap/signin",
        hostname="arnazon.com",
        title="Amazon Sign-In",
        signals=[
            PageSignal(
                id="password_or_otp_input",
                severity="Medium",
                evidence="Sensitive fields present: password=1, otp/pin=0",
                count=1,
            )
        ],
        text_sample="Sign in. Enter your password.",
    )
    res = evaluate_page_signals(req, load_memory())
    assert res["impersonation_detected"] is True
    assert res["overall_risk_score"] == "High"
    assert res["base_score"] >= 92


def test_06_hidden_full_page_overlay_over_button_is_at_least_medium() -> None:
    req = PageAuditRequest(
        url="https://stream-video-portal.net/watch",
        hostname="stream-video-portal.net",
        title="Watch Video",
        signals=[
            PageSignal(
                id="clickjack_overlay",
                severity="High",
                evidence="Transparent high-z-index overlay intercepts clicks over 2 button(s)",
                count=2,
            )
        ],
        text_sample="Click Play to start video.",
    )
    res = evaluate_page_signals(req, load_memory())
    assert res["overall_risk_score"] in ("Medium", "High")
    assert res["base_score"] >= 50
    assert res["is_suspicious"] is True


def test_07_audit_page_missing_or_wrong_token_returns_401_and_403() -> None:
    payload = {
        "url": "https://portal.mycollege.ac.in/login",
        "hostname": "portal.mycollege.ac.in",
        "title": "Student Login",
        "signals": [],
        "text_sample": "Student Login, enter roll number and password",
        "language": "en",
    }
    # 1. Missing X-TrustLens-Token header -> 401
    r_missing = client.post("/api/audit-page", json=payload)
    assert r_missing.status_code == 401

    # 2. Wrong X-TrustLens-Token header -> 403
    r_wrong = client.post(
        "/api/audit-page",
        headers={"X-TrustLens-Token": "wrong-invalid-token-value"},
        json=payload,
    )
    assert r_wrong.status_code == 403

    # 3. Valid X-TrustLens-Token header -> 200
    valid_token = get_extension_token()
    r_ok = client.post(
        "/api/audit-page",
        headers={"X-TrustLens-Token": valid_token},
        json=payload,
    )
    assert r_ok.status_code == 200
    assert r_ok.json()["analysis"]["overall_risk_score"] == "Low"


# --------------------------------------------------------------------------- #
# BUG 3 REQUIRED PYTEST CASES (Feedback & Memory Poisoning Protection)
# --------------------------------------------------------------------------- #
def test_08_pressing_scam_twice_on_same_domain_updates_weights_only_once() -> None:
    initial_mem = load_memory()
    initial_urg = initial_mem["weights"]["urgency_penalty"]

    # First 'confirm_scam' on evil-phish-test.org -> increments urgency_penalty by +1 and blacklists once
    mem1 = apply_user_feedback(
        domain="evil-phish-test.org",
        feedback_type="confirm_scam",
        lesson_note="Fake login portal on evil-phish-test.org",
    )
    assert mem1["weights"]["urgency_penalty"] == initial_urg + 1
    assert mem1["blacklisted_domains"].count("evil-phish-test.org") == 1

    # Second 'confirm_scam' on the same domain -> idempotent (no further weight drift, no duplicate domain)
    mem2 = apply_user_feedback(
        domain="evil-phish-test.org",
        feedback_type="confirm_scam",
        lesson_note="Fake login portal on evil-phish-test.org",
    )
    assert mem2["weights"]["urgency_penalty"] == initial_urg + 1
    assert mem2["blacklisted_domains"].count("evil-phish-test.org") == 1


def test_09_localhost_and_127_0_0_1_and_alert_titles_rejected_as_blacklist_targets() -> None:
    mem = apply_user_feedback(
        domain="127.0.0.1",
        feedback_type="confirm_scam",
        lesson_note="curl -X POST http://127.0.0.1:8000/api/audit-page",
    )
    assert "127.0.0.1" not in mem["blacklisted_domains"]
    assert not any("curl" in l.lower() for l in mem["few_shot_lessons"])

    mem2 = apply_user_feedback(
        domain="TrustLens: Malicious Webpage / Phishing Risk (arnazon.com)",
        feedback_type="confirm_scam",
        lesson_note="⚠️ TrustLens: HIGH RISK INTERCEPTED",
    )
    assert not any("trustlens" in d.lower() for d in mem2["blacklisted_domains"])
    assert not any("trustlens" in l.lower() for l in mem2["few_shot_lessons"])


def test_10_safe_feedback_removes_domain_from_blacklist_and_prevents_readding() -> None:
    apply_user_feedback(domain=" false-alarm-site.org ", feedback_type="confirm_scam")
    assert "false-alarm-site.org" in load_memory()["blacklisted_domains"]

    # User marks it safe -> removed from blacklist and added to user_allowlist
    mem_safe = apply_user_feedback(domain="false-alarm-site.org", feedback_type="false_positive")
    assert "false-alarm-site.org" not in mem_safe["blacklisted_domains"]
    assert "false-alarm-site.org" in mem_safe["user_allowlist"]

    # Subsequent confirm_scam will not re-blacklist a user-allowlisted domain
    mem_retry = apply_user_feedback(domain="false-alarm-site.org", feedback_type="confirm_scam")
    assert "false-alarm-site.org" not in mem_retry["blacklisted_domains"]


def test_11_clipboard_text_carrying_trustlens_marker_or_localhost_is_skipped() -> None:
    marked_report = f"{TRUSTLENS_INTERNAL_MARKER} === TRUSTLENS AI CYBERCRIME INCIDENT REPORT ==="
    assert should_skip_collected_text(marked_report) is True
    assert should_skip_collected_text("⚠️ TrustLens: Malicious Webpage / Phishing Risk") is True
    assert should_skip_collected_text("http://127.0.0.1:8000/demo/dark-patterns") is True
    assert should_skip_collected_text("arnazon.com") is False
    assert should_skip_collected_text("g00gle.com") is False
    assert should_skip_collected_text("https://hdfcbnk.com/login") is False
    assert should_skip_collected_text("5M credited to your account, click here") is False


def test_12_startup_migration_cleans_poisoned_memory_and_clamps_weights() -> None:
    poisoned = {
        "blacklisted_domains": [
            "sbi-kyc-update.xyz",
            "sbi-kyc-update.xyz",
            "127.0.0.1",
            "localhost",
            "192.168.1.10",
            "TrustLens: Malicious Webpage...",
        ],
        "user_allowlist": ["mycollege.ac.in"],
        "weights": {
            "urgency_penalty": 999,  # Drifted way above base (25) + 10
            "missing_https_penalty": 1,  # Drifted way below base (20) - 10
        },
        "few_shot_lessons": [
            "curl -X POST http://127.0.0.1:8000/api/audit",
            "TrustLens: HIGH RISK INTERCEPTED",
            "Valid short lesson about homoglyph domains.",
            "Valid short lesson about homoglyph domains.",
        ],
    }
    save_memory(poisoned)
    cleaned = migrate_and_clean_memory_on_startup()
    assert cleaned["blacklisted_domains"] == ["sbi-kyc-update.xyz"]
    assert cleaned["weights"]["urgency_penalty"] == BASE_WEIGHTS["urgency_penalty"] + 10
    assert cleaned["weights"]["missing_https_penalty"] == BASE_WEIGHTS["missing_https_penalty"] - 10
    assert cleaned["few_shot_lessons"] == ["Valid short lesson about homoglyph domains."]


def test_13_blacklist_hit_sets_floor_80_and_only_describes_detected_signals() -> None:
    req = PageAuditRequest(
        url="https://sbi-kyc-update.xyz/welcome",
        hostname="sbi-kyc-update.xyz",
        title="Welcome",
        signals=[],
        text_sample="Welcome to our portal.",
    )
    res = evaluate_page_signals(req, load_memory())
    # Blacklist hit sets floor 80 (plus suspicious TLD if applicable, never fabricated timer/checkbox text)
    assert res["hard_floor"] >= 80
    assert res["overall_risk_score"] == "High"
    expl = f"{res['calm_message']} {res['how_it_affects_user']}".lower()
    assert "countdown" not in expl
    assert "checkbox" not in expl
    assert "win+r" not in expl
