"""Pytest suite verifying all 6 plain-language and backwards-compatibility requirements:
(a) No template string contains a banned word.
(b) No template sentence exceeds 15 words.
(c) simple_text_check catches 'homoglyph' and long sentences (>15 words).
(d) Every signal type in PLAIN_SIGNAL_TEMPLATES and PAGE_SIGNAL_TEMPLATES has both EN and HI text.
(e) verdict_line is present for Low, Medium, and High results.
(f) Old memory/feed items without verdict_line still validate and populate verdict_line automatically.
"""
from __future__ import annotations

from ai_auditor import PhishingAuditResult
from heuristics import (
    PLAIN_SIGNAL_TEMPLATES,
    evaluate_heuristics,
    simple_text_check,
)
from page_analysis import PAGE_SIGNAL_TEMPLATES, PageAuditRequest, PageSignal, evaluate_page_signals


def test_a_and_b_no_template_contains_banned_word_or_long_sentence() -> None:
    for key, tpl in PLAIN_SIGNAL_TEMPLATES.items():
        for field in ("verdict_en", "calm_en", "about_en", "seems_en", "affects_en", "explain_en"):
            ok, violations = simple_text_check(tpl[field], "en")
            assert ok, f"PLAIN_SIGNAL_TEMPLATES[{key}][{field}] failed: {violations}"
        for step in tpl["actions_en"]:
            ok, violations = simple_text_check(step, "en")
            assert ok, f"PLAIN_SIGNAL_TEMPLATES[{key}] action_en '{step}' failed: {violations}"

        for field in ("verdict_hi", "calm_hi", "about_hi", "seems_hi", "affects_hi", "explain_hi"):
            ok, violations = simple_text_check(tpl[field], "hi")
            assert ok, f"PLAIN_SIGNAL_TEMPLATES[{key}][{field}] failed: {violations}"
        for step in tpl["actions_hi"]:
            ok, violations = simple_text_check(step, "hi")
            assert ok, f"PLAIN_SIGNAL_TEMPLATES[{key}] action_hi '{step}' failed: {violations}"

    for key, ptpl in PAGE_SIGNAL_TEMPLATES.items():
        for field in ("about_en", "seems_en", "affects_en", "explain_en", "action_en"):
            ok, violations = simple_text_check(ptpl[field], "en")
            assert ok, f"PAGE_SIGNAL_TEMPLATES[{key}][{field}] failed: {violations}"
        for field in ("about_hi", "seems_hi", "affects_hi", "explain_hi", "action_hi"):
            ok, violations = simple_text_check(ptpl[field], "hi")
            assert ok, f"PAGE_SIGNAL_TEMPLATES[{key}][{field}] failed: {violations}"


def test_c_simple_text_check_catches_homoglyph_and_long_sentences() -> None:
    ok_bad_word, v1 = simple_text_check("Visual homoglyph substitution detected in brand domain.", "en")
    assert ok_bad_word is False
    assert any("homoglyph" in item for item in v1)
    assert any("domain" in item for item in v1)

    long_sentence = (
        "This single sentence has way more than fifteen words in a row so that our "
        "plain language checker will flag it right away."
    )
    ok_long, v2 = simple_text_check(long_sentence, "en")
    assert ok_long is False
    assert any("sentence_too_long" in item for item in v2)

    ok_good, v3 = simple_text_check(
        "The website name is spelled wrong on purpose. It says arnazon, not amazon. It is fake.",
        "en",
    )
    assert ok_good is True
    assert v3 == []


def test_d_every_signal_type_has_en_and_hi_text() -> None:
    for key, tpl in PLAIN_SIGNAL_TEMPLATES.items():
        assert tpl.get("about_en") and tpl.get("about_hi"), f"Missing about EN/HI in {key}"
        assert tpl.get("seems_en") and tpl.get("seems_hi"), f"Missing seems EN/HI in {key}"
        assert tpl.get("affects_en") and tpl.get("affects_hi"), f"Missing affects EN/HI in {key}"
        assert tpl.get("calm_en") and tpl.get("calm_hi"), f"Missing calm EN/HI in {key}"
        assert tpl.get("actions_en") and tpl.get("actions_hi"), f"Missing actions EN/HI in {key}"

    for key, ptpl in PAGE_SIGNAL_TEMPLATES.items():
        assert ptpl.get("about_en") and ptpl.get("about_hi"), f"Missing about EN/HI in page signal {key}"
        assert ptpl.get("seems_en") and ptpl.get("seems_hi"), f"Missing seems EN/HI in page signal {key}"
        assert ptpl.get("affects_en") and ptpl.get("affects_hi"), f"Missing affects EN/HI in page signal {key}"
        assert ptpl.get("action_en") and ptpl.get("action_hi"), f"Missing action EN/HI in page signal {key}"


def test_e_verdict_line_present_for_low_medium_and_high() -> None:
    # Low
    res_low = evaluate_heuristics("482910 is your One Time Password (OTP) for SBI. Do NOT share this OTP with anyone.")
    assert res_low["verdict_line"] == "✅ This looks safe"
    assert res_low["verdict_line_hi"] == "✅ यह सुरक्षित लगता है"

    # Medium
    req_med = PageAuditRequest(
        url="https://unknown-site.example/login",
        hostname="unknown-site.example",
        title="Sign In",
        signals=[],
        text_sample="Enter your password",
    )
    res_med = evaluate_page_signals(req_med)
    assert res_med["overall_risk_score"] == "Medium"
    assert res_med["verdict_line"] == "⚠️ Be careful"
    assert res_med["verdict_line_hi"] == "⚠️ सावधान रहें"

    # High
    res_high = evaluate_heuristics("arnazon.com")
    assert res_high["verdict_line"] == "🛑 This is a scam"
    assert res_high["verdict_line_hi"] == "🛑 यह एक धोखा है"


def test_f_old_items_without_verdict_line_still_load_and_render() -> None:
    old_payload = {
        "is_suspicious": True,
        "overall_risk_score": "High",
        "numeric_risk_score": 92,
        "fraud_category": "Fake Website",
        "what_input_is_about": "What this is: A fake website link.",
        "what_it_seems_to_be": "What it pretends to be: Amazon.",
        "how_it_affects_user": "What could happen to you: They can steal your password.",
        "confidence_score_explanation": "Score 92/100.",
        "dark_pattern_detected": "None",
        "calm_down_message": "Stay calm. Nothing bad has happened yet.",
        "indicators": [],
        "recommended_actions": ["Do not open this link."],
    }
    parsed = PhishingAuditResult.model_validate(old_payload)
    assert parsed.verdict_line == "🛑 This is a scam"
    assert parsed.verdict_line_hi == "🛑 यह एक धोखा है"