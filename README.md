# JWT Security Analyzer

![CI](https://github.com/KaanTuran28/JWT-Security-Analyzer/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A dependency-free CLI that decodes a JWT and flags common security issues — entirely offline, with no signature verification against a real key. Meant for reviewing tokens you already have (e.g. from a pentest engagement, a bug bounty target, or your own application), not as a JWT library.

### Overview

- Decodes the header and payload (base64url, no external JWT library needed).
- Flags `"alg": "none"` — the classic signature-bypass vector.
- Attempts to crack `HS256`/`HS384`/`HS512` signatures against a small built-in wordlist of common/weak secrets (pure `hmac`/`hashlib`, no network calls).
- Flags `jku` / `x5u` / `jwk` header fields — these let an attacker point a careless verifier at a signing key they control (a real, repeatedly-CVE'd vulnerability class).
- Flags a missing `exp` claim, and an unusually long `exp`-minus-`iat` lifetime.
- Flags sensitive-looking data (`password`, `ssn`, `api_key`, ...) placed directly in the payload — a JWT payload is only base64url-**encoded**, not encrypted, so anyone holding the token can read it.

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd JWT-Security-Analyzer
pip install -e .
```

This installs a `jwt-security-analyzer` command. You can also run the script directly with `python jwt_security_analyzer.py` without installing.

### Usage

```bash
jwt-security-analyzer --token "eyJhbGciOiJIUzI1NiIs..." --output report.md
jwt-security-analyzer --file sample_tokens/weak_secret_token.txt --format json --output report.json
cat token.txt | jwt-security-analyzer --output report.md
```

| Flag | Default | Description |
|---|---|---|
| `--token` | — | The JWT string to analyze |
| `--file` | — | Path to a file containing the JWT (used instead of `--token`) |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

If neither `--token` nor `--file` is given, the token is read from stdin.

### CI Integration

Run this in a pentest/bug-bounty pipeline against tokens harvested during recon, or as a regression check that your own auth service never issues a weak token:

```bash
jwt-security-analyzer --file captured_token.txt --fail-on high
```

```yaml
# GitHub Actions step
- name: Check captured token for known JWT weaknesses
  run: jwt-security-analyzer --file captured_token.txt --fail-on high
```

Default is `none` (always exits `0`) so ad-hoc analysis is unaffected. A malformed (non-JWT) input exits `2` regardless of `--fail-on`.

### Sample Tokens

All in [`sample_tokens/`](./sample_tokens), each isolating one finding:

| File | Demonstrates | Findings |
|---|---|---|
| [`alg_none_token.txt`](./sample_tokens/alg_none_token.txt) | `"alg": "none"` | 1 HIGH |
| [`weak_secret_token.txt`](./sample_tokens/weak_secret_token.txt) | HS256 signed with `"secret"` | 1 HIGH |
| [`jku_header_token.txt`](./sample_tokens/jku_header_token.txt) | External key reference (`jku`) | 1 HIGH |
| [`sensitive_claims_token.txt`](./sample_tokens/sensitive_claims_token.txt) | `password`/`ssn` in payload, no `exp` | 3 MEDIUM |
| [`long_lived_token.txt`](./sample_tokens/long_lived_token.txt) | 10-year token lifetime | 1 LOW |
| [`clean_token.txt`](./sample_tokens/clean_token.txt) | Strong secret, short lifetime, no sensitive claims | 0 findings |

See [`sample_report.md`](./sample_report.md) — real output from running the tool against `weak_secret_token.txt`.

### How the secret-cracking works

For `HS256`/`HS384`/`HS512` tokens, the tool recomputes `HMAC(secret, header.payload)` for each entry in a small built-in wordlist and compares it (constant-time, via `hmac.compare_digest`) against the token's actual signature. This is exactly what dedicated tools like `jwt_tool` or `hashcat`'s JWT mode do at a larger scale — here it's a ~15-entry demonstration list, not a real cracking dictionary.

### Limitations

This is a **triage** tool, not a JWT library: it does not verify a signature against a real, correct key (there's no key to verify against when reviewing someone else's token), does not support asymmetric-algorithm signature verification, and its weak-secret wordlist is intentionally small. A "no findings" result means none of these specific heuristics fired — it is not a guarantee the token is secure.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
JWT-Security-Analyzer/
├── jwt_security_analyzer.py
├── pyproject.toml
├── sample_tokens/
│   ├── alg_none_token.txt
│   ├── weak_secret_token.txt
│   ├── jku_header_token.txt
│   ├── sensitive_claims_token.txt
│   ├── long_lived_token.txt
│   └── clean_token.txt
├── sample_report.md
├── tests/
│   └── test_jwt_security_analyzer.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Bir JWT'yi çözümleyip yaygın güvenlik sorunlarını işaretleyen, bağımlılıksız bir CLI — tamamen çevrimdışı çalışır, gerçek bir anahtara karşı imza doğrulaması yapmaz. Zaten elinizde olan token'ları incelemek içindir (ör. bir pentest çalışması, bug bounty hedefi veya kendi uygulamanızdan gelen token'lar) — bir JWT kütüphanesi değildir.

### Genel Bakış

- Header ve payload'ı çözümler (base64url, harici bir JWT kütüphanesine gerek yoktur).
- `"alg": "none"` durumunu işaretler — klasik imza atlatma (bypass) vektörü.
- `HS256`/`HS384`/`HS512` imzalarını, yaygın/zayıf sırlardan oluşan küçük, dahili bir kelime listesine karşı kırmayı dener (saf `hmac`/`hashlib`, ağ çağrısı yoktur).
- `jku` / `x5u` / `jwk` header alanlarını işaretler — bunlar, dikkatsiz bir doğrulayıcıyı saldırganın kontrol ettiği bir imzalama anahtarına yönlendirmesine izin verir (gerçek, tekrar tekrar CVE almış bir zafiyet sınıfı).
- Eksik bir `exp` claim'ini ve alışılmadık derecede uzun bir `exp`-eksi-`iat` yaşam süresini işaretler.
- Payload'a doğrudan yerleştirilmiş hassas görünen verileri (`password`, `ssn`, `api_key`, ...) işaretler — bir JWT payload'ı yalnızca base64url ile **kodlanmıştır** (encoded), şifrelenmiş değildir; dolayısıyla token'ı elinde bulunduran herkes içeriğini okuyabilir.

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd JWT-Security-Analyzer
pip install -e .
```

Bu, bir `jwt-security-analyzer` komutu kurar. Kurulum yapmadan da doğrudan `python jwt_security_analyzer.py` ile çalıştırabilirsiniz.

### Kullanım

```bash
jwt-security-analyzer --token "eyJhbGciOiJIUzI1NiIs..." --output report.md
jwt-security-analyzer --file sample_tokens/weak_secret_token.txt --format json --output report.json
cat token.txt | jwt-security-analyzer --output report.md
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--token` | — | Analiz edilecek JWT dizesi |
| `--file` | — | JWT içeren dosyanın yolu (`--token` yerine kullanılır) |
| `--output` | `sample_report.md` | Raporun yazılacağı yol |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem derecesinde/üzerinde bir bulgu varsa çıkış kodu `1` |

Ne `--token` ne de `--file` verilmezse, token stdin'den okunur.

### CI Entegrasyonu

Bunu, keşif (recon) sırasında toplanan token'lara karşı bir pentest/bug bounty pipeline'ında, ya da kendi kimlik doğrulama servisinizin asla zayıf bir token üretmediğini doğrulayan bir regresyon kontrolü olarak çalıştırın:

```bash
jwt-security-analyzer --file captured_token.txt --fail-on high
```

```yaml
# GitHub Actions step
- name: Check captured token for known JWT weaknesses
  run: jwt-security-analyzer --file captured_token.txt --fail-on high
```

Varsayılan `none`'dır (her zaman `0` ile çıkar), böylece ad-hoc analiz etkilenmez. Bozuk (JWT olmayan) bir girdi, `--fail-on` ayarından bağımsız olarak `2` ile çıkar.

### Örnek Token'lar

Hepsi [`sample_tokens/`](./sample_tokens) içinde, her biri tek bir bulguyu izole eder:

| Dosya | Gösterdiği | Bulgular |
|---|---|---|
| [`alg_none_token.txt`](./sample_tokens/alg_none_token.txt) | `"alg": "none"` | 1 HIGH |
| [`weak_secret_token.txt`](./sample_tokens/weak_secret_token.txt) | `"secret"` ile imzalanmış HS256 | 1 HIGH |
| [`jku_header_token.txt`](./sample_tokens/jku_header_token.txt) | Harici anahtar referansı (`jku`) | 1 HIGH |
| [`sensitive_claims_token.txt`](./sample_tokens/sensitive_claims_token.txt) | Payload'da `password`/`ssn`, `exp` yok | 3 MEDIUM |
| [`long_lived_token.txt`](./sample_tokens/long_lived_token.txt) | 10 yıllık token yaşam süresi | 1 LOW |
| [`clean_token.txt`](./sample_tokens/clean_token.txt) | Güçlü sır, kısa yaşam süresi, hassas claim yok | 0 bulgu |

Aracın `weak_secret_token.txt`'e karşı çalıştırılmasından elde edilen gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın.

### Sır kırma (secret-cracking) nasıl çalışır

`HS256`/`HS384`/`HS512` token'ları için araç, dahili küçük kelime listesindeki her giriş için `HMAC(secret, header.payload)` değerini yeniden hesaplar ve bunu (sabit zamanlı olarak, `hmac.compare_digest` üzerinden) token'ın gerçek imzasıyla karşılaştırır. Bu, `jwt_tool` veya `hashcat`'in JWT modu gibi özel araçların daha büyük ölçekte tam olarak yaptığı şeydir — burada ise gerçek bir kırma sözlüğü değil, yaklaşık 15 girişlik bir gösterim listesidir.

### Sınırlamalar

Bu bir JWT kütüphanesi değil, bir **triyaj (triage)** aracıdır: gerçek, doğru bir anahtara karşı imza doğrulaması yapmaz (başkasının token'ını incelerken doğrulanacak bir anahtar yoktur), asimetrik algoritma imza doğrulamasını desteklemez ve zayıf-sır kelime listesi kasıtlı olarak küçüktür. "Bulgu yok" sonucu, bu belirli sezgisel kontrollerin hiçbirinin tetiklenmediği anlamına gelir — token'ın güvenli olduğunun garantisi değildir.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
JWT-Security-Analyzer/
├── jwt_security_analyzer.py
├── pyproject.toml
├── sample_tokens/
│   ├── alg_none_token.txt
│   ├── weak_secret_token.txt
│   ├── jku_header_token.txt
│   ├── sensitive_claims_token.txt
│   ├── long_lived_token.txt
│   └── clean_token.txt
├── sample_report.md
├── tests/
│   └── test_jwt_security_analyzer.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
