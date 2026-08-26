# JWT Security Analysis Report

- **Source:** sample_tokens/weak_secret_token.txt
- **Algorithm:** HS256
- **Findings:** 1 HIGH, 0 MEDIUM, 0 LOW

## Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

## Payload
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1700000000,
  "exp": 1700003600
}
```

## Findings

| Severity | Check | Detail | Recommendation |
|---|---|---|---|
| HIGH | weak_hmac_secret | The signature validates against a common/weak secret ("secret") from a small built-in wordlist — anyone can forge arbitrary tokens signed with this secret. | Use a long, randomly generated secret (32+ bytes), or switch to an asymmetric algorithm (RS256/ES256) so the signing key never has to be shared with verifiers. |
