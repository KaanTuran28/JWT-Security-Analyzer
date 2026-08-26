#!/usr/bin/env python3
"""Offline JWT security analyzer.

Decodes a JWT's header and payload (no signature verification against a real
key — this is a triage/review tool, not an authentication library) and flags
common issues: "alg: none", signatures crackable against a small built-in
weak-secret wordlist, external/embedded key references (jku/x5u/jwk) that
enable key-confusion attacks, missing or excessive expiration, and
sensitive-looking data placed directly in the payload.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys

# A handful of secrets seen in real-world misconfigurations, tutorials, and
# leaked source — enough to demonstrate the technique, not a real cracking list.
COMMON_JWT_SECRETS = [
    "secret",
    "your-256-bit-secret",
    "jwt_secret",
    "jwtsecret",
    "password",
    "123456",
    "changeme",
    "supersecret",
    "secretkey",
    "mysecret",
    "qwerty",
    "admin",
    "letmein",
    "test",
    "key",
]

SENSITIVE_CLAIM_KEYS = {
    "password",
    "pwd",
    "ssn",
    "social_security_number",
    "credit_card",
    "credit_card_number",
    "api_key",
    "apikey",
    "secret",
    "private_key",
}

HMAC_DIGESTS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

ONE_YEAR_SECONDS = 365 * 24 * 3600


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("expected 3 dot-separated segments (header.payload.signature)")
    header_b64, payload_b64, signature_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    signature = b64url_decode(signature_b64) if signature_b64 else b""
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return header, payload, signature, signing_input


def crack_hmac_secret(alg: str, signing_input: bytes, signature: bytes, wordlist=COMMON_JWT_SECRETS):
    digestmod = HMAC_DIGESTS.get(alg.upper())
    if digestmod is None or not signature:
        return None
    for secret in wordlist:
        candidate = hmac.new(secret.encode("utf-8"), signing_input, digestmod).digest()
        if hmac.compare_digest(candidate, signature):
            return secret
    return None


def finding(severity: str, check: str, reason: str, recommendation: str) -> dict:
    return {"severity": severity, "check": check, "reason": reason, "recommendation": recommendation}


def analyze(token: str) -> dict:
    header, payload, signature, signing_input = decode_jwt(token)
    findings = []
    alg = str(header.get("alg", "")).strip()

    if alg.lower() == "none":
        findings.append(finding(
            "HIGH", "alg_none",
            'Header declares "alg": "none" — a token with an empty signature will be accepted by any '
            "verifier that trusts the client-supplied algorithm.",
            'Reject "none" explicitly and pin verification to one expected algorithm; never take '
            "the alg to use from the token itself.",
        ))

    for header_key in ("jku", "x5u", "jwk"):
        if header_key in header:
            findings.append(finding(
                "HIGH", "external_key_reference",
                f'Header specifies "{header_key}", pointing the verifier at an external or embedded '
                "signing key. If the verifier fetches or trusts this without an allowlist, an attacker "
                "can point it at a key they control and forge valid tokens.",
                f'Ignore "{header_key}" or strictly allowlist it server-side; never resolve a '
                "verification key from a location the token itself supplies.",
            ))

    cracked = crack_hmac_secret(alg, signing_input, signature)
    if cracked is not None:
        findings.append(finding(
            "HIGH", "weak_hmac_secret",
            f'The signature validates against a common/weak secret ("{cracked}") from a small built-in '
            "wordlist — anyone can forge arbitrary tokens signed with this secret.",
            "Use a long, randomly generated secret (32+ bytes), or switch to an asymmetric algorithm "
            "(RS256/ES256) so the signing key never has to be shared with verifiers.",
        ))

    if "exp" not in payload:
        findings.append(finding(
            "MEDIUM", "missing_exp",
            'No "exp" (expiration) claim — this token never expires and remains valid indefinitely if leaked.',
            'Always set a short "exp" claim appropriate to the token\'s purpose.',
        ))
    elif "iat" in payload:
        try:
            lifetime = float(payload["exp"]) - float(payload["iat"])
        except (TypeError, ValueError):
            lifetime = None
        if lifetime is not None and lifetime > ONE_YEAR_SECONDS:
            days = round(lifetime / 86400)
            findings.append(finding(
                "LOW", "excessive_lifetime",
                f"Token lifetime is about {days} days — an unusually long validity window widens the "
                "exposure if the token leaks.",
                "Shorten the token lifetime and use a refresh-token flow for long-lived sessions.",
            ))

    for key in sorted(k for k in payload if str(k).lower() in SENSITIVE_CLAIM_KEYS):
        findings.append(finding(
            "MEDIUM", "sensitive_claim",
            f'Payload claim "{key}" looks like sensitive data. A JWT payload is only base64url-encoded, '
            "not encrypted — anyone who can read the token can read this value.",
            "Never place secrets, passwords, or raw PII in a JWT payload; store an opaque reference "
            "and look up the real value server-side.",
        ))

    return {"header": header, "payload": payload, "algorithm": alg, "findings": findings}


def build_report(result: dict, label: str) -> str:
    findings = result["findings"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] == "LOW"]

    lines = [
        "# JWT Security Analysis Report",
        "",
        f"- **Source:** {label}",
        f"- **Algorithm:** {result['algorithm'] or '(missing)'}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW",
        "",
        "## Header",
        "```json",
        json.dumps(result["header"], indent=2, ensure_ascii=False),
        "```",
        "",
        "## Payload",
        "```json",
        json.dumps(result["payload"], indent=2, ensure_ascii=False),
        "```",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += ["| Severity | Check | Detail | Recommendation |", "|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f in sorted(findings, key=lambda f: order[f["severity"]]):
            detail = f["reason"].replace("|", "\\|")
            recommendation = f["recommendation"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['check']} | {detail} | {recommendation} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(result: dict, label: str) -> str:
    findings = result["findings"]
    payload = {
        "source": label,
        "algorithm": result["algorithm"],
        "header": result["header"],
        "payload": result["payload"],
        "summary": {
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a JWT for common security issues (offline; does not verify against a real key)."
    )
    parser.add_argument("--token", help="The JWT string to analyze")
    parser.add_argument("--file", help="Path to a file containing the JWT string (else reads --token or stdin)")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Report output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    if args.token:
        token = args.token
        label = "(inline token)"
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
        label = args.file
    else:
        token = sys.stdin.read().strip()
        label = "(stdin)"

    try:
        result = analyze(token)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"Error: not a valid JWT ({exc})", file=sys.stderr)
        return 2

    report = (
        build_json_report(result, label) if args.format == "json" else build_report(result, label)
    )
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    high_count = sum(1 for f in result["findings"] if f["severity"] == "HIGH")
    medium_count = sum(1 for f in result["findings"] if f["severity"] == "MEDIUM")
    print(f"Algorithm: {result['algorithm']} | Findings: {high_count} HIGH, {medium_count} MEDIUM")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
