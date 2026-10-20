"""Pytest suite verifying all 7 pie-chart & score_breakdown requirements:
1. Breakdown points sum strictly to numeric_risk_score (or include 'Other small things').
2. Zero-signal page gives the single safe slice ('Nothing suspicious found', points=0).
3. github.com/login gives a safe single-slice chart (points=0).
4. All slice labels in PLAIN_SLICE_LABELS and DASHBOARD_BREAKDOWN_CATEGORIES pass simple_text_check in EN and HI.
5. Old items without score_breakdown load and render without crashing.
6. /api/stats/breakdown enforces X-TrustLens-Token (401 missing, 403 invalid, 200 valid) and returns bounded data.
7. Multi-signal webpages produce distinct real slices summing to the combined score.
"""
from __future__ import annotations

import copy
import pytest
from fastapi.testclient import TestClient

import ai_auditor
from ai_auditor import DEFAULT_MEMORY, PhishingAuditResult, build_offline_heuristic_result, save_memory
from collectors import get_extension_token
from heuristics import (
    PLAIN_SLICE_LABELS,
    build_normalized_score_breakdown,
    evaluate_heuristics,
    simple_text_check,
)
from main import DASHBOARD_BREAKDOWN_CATEGORIES, app
from page_analysis import PageAuditRequest, PageSignal, evaluate_page_signals

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_memory(tmp_path, monkeypatch):
    test_mem_file = tmp_path / "test_breakdown_memory.json"
    monkeypatch.setattr(ai_auditor, "MEMORY_FILE", str(test_mem_file))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    save_memory(copy.deepcopy(DEFAULT_MEMORY))
    yield


def test_01_breakdown_points_sum_to_numeric_score_or_include_other() -> None:
    # Case A: Homoglyph URL
    h1 = evaluate_heuristics("arnazon.com")
    res1 = build_offline_heuristic_result(h1)
    assert res1.numeric_risk_score > 0
    assert sum(s.points for s in res1.score_breakdown) == res1.numeric_risk_score

    # Case B: When final score is higher than individual slice points, 'other_small_things' pads the remainder
    padded = build_normalized_score_breakdown(
        [{"key": "strange_link_ending", "points": 40, "severity": "Medium"}],
        final_score=75,
    )
    assert sum(s["points"] for s in padded) == 75
    assert any(s["key"] == "other_small_things" and s["points"] == 35 for s in padded)


def test_02_zero_signal_page_gives_single_safe_slice() -> None:
    req = PageAuditRequest(
        url="https://clean-blog.example/post",
        hostname="clean-blog.example",
        title="Welcome to My Blog",
        signals=[],
        text_sample="Today we are baking bread at home.",
    )
    heur = evaluate_page_signals(req)
    res = build_offline_heuristic_result(heur)
    assert res.numeric_risk_score == 0
    assert len(res.score_breakdown) == 1
    assert res.score_breakdown[0].key == "nothing_suspicious"
    assert res.score_breakdown[0].label_en == "Nothing suspicious found"
    assert res.score_breakdown[0].points == 0


def test_03_github_login_gives_safe_chart() -> None:
    req = PageAuditRequest(
        url="https://github.com/login",
        hostname="github.com",
        title="Sign in to GitHub",
        signals=[],
        text_sample="Username or email address. Password.",
    )
    heur = evaluate_page_signals(req)
    res = build_offline_heuristic_result(heur)
    assert res.overall_risk_score == "Low"
    assert res.numeric_risk_score == 0
    assert len(res.score_breakdown) == 1
    assert res.score_breakdown[0].key == "nothing_suspicious"


def test_04_all_slice_and_dashboard_labels_pass_simple_text_check_in_en_and_hi() -> None:
    for key, (lbl_en, lbl_hi) in PLAIN_SLICE_LABELS.items():
        ok_en, v_en = simple_text_check(lbl_en, "en")
        ok_hi, v_hi = simple_text_check(lbl_hi, "hi")
        assert ok_en, f"Slice label_en [{key}]='{lbl_en}' failed: {v_en}"
        assert ok_hi, f"Slice label_hi [{key}]='{lbl_hi}' failed: {v_hi}"

    for key, lbl_en, lbl_hi in DASHBOARD_BREAKDOWN_CATEGORIES:
        ok_en, v_en = simple_text_check(lbl_en, "en")
        ok_hi, v_hi = simple_text_check(lbl_hi, "hi")
        assert ok_en, f"Dashboard category EN [{key}]='{lbl_en}' failed: {v_en}"
        assert ok_hi, f"Dashboard category HI [{key}]='{lbl_hi}' failed: {v_hi}"


def test_05_old_items_without_score_breakdown_do_not_crash() -> None:
    old_item = {
        "is_suspicious": True,
        "overall_risk_score": "High",
        "numeric_risk_score": 90,
        "fraud_category": "Fake Link",
        "what_input_is_about": "What this is: A fake link.",
        "what_it_seems_to_be": "What it pretends to be: A bank page.",
        "how_it_affects_user": "What could happen to you: They can steal your money.",
        "confidence_score_explanation": "Score 90/100.",
        "dark_pattern_detected": "None",
        "calm_down_message": "Stay calm.",
        "indicators": [],
        "recommended_actions": ["Do not click."],
    }
    parsed = PhishingAuditResult.model_validate(old_item)
    assert parsed.score_breakdown == []
    assert parsed.verdict_line == "🛑 This is a scam"


def test_06_stats_breakdown_endpoint_enforces_token_and_returns_bounded_data() -> None:
    # 1. Missing token -> 401
    r_missing = client.get("/api/stats/breakdown")
    assert r_missing.status_code == 401

    # 2. Wrong token -> 403
    r_wrong = client.get("/api/stats/breakdown", headers={"X-TrustLens-Token": "wrong-token"})
    assert r_wrong.status_code == 403

    # 3. Valid token -> 200 with 6 plain-language categories
    tok = get_extension_token()
    client.post("/api/audit", json={"input_text": "arnazon.com", "channel": "test"})
    r_ok = client.get("/api/stats/breakdown", headers={"X-TrustLens-Token": tok})
    assert r_ok.status_code == 200
    body = r_ok.json()
    assert body["status"] == "ok"
    assert len(body["categories"]) == 6
    keys = {c["key"] for c in body["categories"]}
    assert keys == {"fake_links", "fake_refunds", "otp_or_password", "urgent_money", "page_tricks", "safe_items"}


def test_07_multi_signal_webpage_produces_real_slices_summing_to_score() -> None:
    req = PageAuditRequest(
        url="https://tricky-shop.xyz/checkout",
        hostname="tricky-shop.xyz",
        title="Flash Checkout",
        signals=[
            PageSignal(id="resetting_countdown_timer", severity="Medium", evidence="Timer reset", count=1),
            PageSignal(id="prechecked_addon_box", severity="Medium", evidence="Ticked addon", count=1),
            PageSignal(id="confirm_shaming", severity="Medium", evidence="No I hate saving", count=1),
        ],
    )
    heur = evaluate_page_signals(req)
    res = build_offline_heuristic_result(heur)
    assert len(res.score_breakdown) >= 3
    assert sum(s.points for s in res.score_breakdown) == res.numeric_risk_score
