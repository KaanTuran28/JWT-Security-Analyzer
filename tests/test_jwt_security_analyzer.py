import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jwt_security_analyzer import analyze, build_json_report, build_report, decode_jwt, main

SAMPLES = Path(__file__).resolve().parent.parent / "sample_tokens"


def load(name):
    return (SAMPLES / name).read_text(encoding="utf-8").strip()


def test_decode_jwt_splits_header_and_payload():
    header, payload, signature, signing_input = decode_jwt(load("clean_token.txt"))
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user-42"
    assert signature
    assert signing_input.count(b".") == 1


def test_decode_jwt_rejects_malformed_token():
    try:
        decode_jwt("not-a-jwt")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "3 dot-separated segments" in str(exc)


def test_alg_none_flagged_high():
    result = analyze(load("alg_none_token.txt"))
    checks = {f["check"] for f in result["findings"]}
    assert "alg_none" in checks
    alg_none = next(f for f in result["findings"] if f["check"] == "alg_none")
    assert alg_none["severity"] == "HIGH"


def test_weak_hmac_secret_is_cracked():
    result = analyze(load("weak_secret_token.txt"))
    cracked = next(f for f in result["findings"] if f["check"] == "weak_hmac_secret")
    assert cracked["severity"] == "HIGH"
    assert '"secret"' in cracked["reason"]


def test_clean_token_signed_with_strong_secret_has_no_weak_secret_finding():
    result = analyze(load("clean_token.txt"))
    checks = {f["check"] for f in result["findings"]}
    assert "weak_hmac_secret" not in checks
    assert "alg_none" not in checks
    assert "missing_exp" not in checks


def test_jku_header_flagged_high():
    result = analyze(load("jku_header_token.txt"))
    jku_finding = next(f for f in result["findings"] if f["check"] == "external_key_reference")
    assert jku_finding["severity"] == "HIGH"
    assert "jku" in jku_finding["reason"]


def test_missing_exp_flagged_medium():
    result = analyze(load("sensitive_claims_token.txt"))
    missing_exp = next(f for f in result["findings"] if f["check"] == "missing_exp")
    assert missing_exp["severity"] == "MEDIUM"


def test_sensitive_claims_flagged_for_password_and_ssn():
    result = analyze(load("sensitive_claims_token.txt"))
    sensitive = [f for f in result["findings"] if f["check"] == "sensitive_claim"]
    flagged_claims = {f["reason"] for f in sensitive}
    assert len(sensitive) == 2
    assert any("password" in reason for reason in flagged_claims)
    assert any("ssn" in reason for reason in flagged_claims)
    assert all(f["severity"] == "MEDIUM" for f in sensitive)


def test_excessive_lifetime_flagged_low():
    result = analyze(load("long_lived_token.txt"))
    lifetime_finding = next(f for f in result["findings"] if f["check"] == "excessive_lifetime")
    assert lifetime_finding["severity"] == "LOW"
    assert "days" in lifetime_finding["reason"]


def test_short_lived_token_has_no_lifetime_finding():
    result = analyze(load("clean_token.txt"))
    checks = {f["check"] for f in result["findings"]}
    assert "excessive_lifetime" not in checks


def test_build_report_includes_header_and_payload_json():
    result = analyze(load("weak_secret_token.txt"))
    report = build_report(result, "weak_secret_token.txt")
    assert '"alg": "HS256"' in report
    assert '"name": "John Doe"' in report
    assert "weak_hmac_secret" in report


def test_build_report_clean_token_says_no_issues():
    result = analyze(load("clean_token.txt"))
    report = build_report(result, "clean_token.txt")
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    result = analyze(load("weak_secret_token.txt"))
    payload = json.loads(build_json_report(result, "weak_secret_token.txt"))
    assert payload["algorithm"] == "HS256"
    assert payload["summary"]["high"] == sum(1 for f in result["findings"] if f["severity"] == "HIGH")
    assert len(payload["findings"]) == len(result["findings"])


def run_main(monkeypatch, tmp_path, token_file, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["jwt_security_analyzer.py", "--file", str(SAMPLES / token_file), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_alg_none_token(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "alg_none_token.txt", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_clean_token(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "clean_token.txt", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, "alg_none_token.txt", []) == 0


def test_main_returns_2_for_malformed_token(monkeypatch, tmp_path):
    out = str(tmp_path / "out.md")
    argv = ["jwt_security_analyzer.py", "--token", "not-a-jwt", "--output", out]
    monkeypatch.setattr(sys, "argv", argv)
    assert main() == 2
