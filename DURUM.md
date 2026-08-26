# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: JWT'leri offline analiz eden CLI aracı — `alg: none`, zayıf HS256/384/512 secret'ları (küçük bir wordlist'e karşı gerçek HMAC crack denemesi), `jku`/`x5u`/`jwk` header'ları üzerinden key-confusion riski, eksik/aşırı uzun `exp`, payload'da düz metin hassas veri (`password`, `ssn`, `api_key`, ...). Hiçbir ağ çağrısı yok, hiçbir üçüncü parti JWT kütüphanesi kullanılmadı (`hmac`/`hashlib`/`base64`/`json` stdlib).
- Dosya: `jwt_security_analyzer.py`, 6 örnek token (`sample_tokens/`, her biri tek bir bulguyu izole ediyor — Python'la gerçek HMAC-SHA256 imzalarla üretildi), `tests/test_jwt_security_analyzer.py` (17 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}` (portföydeki diğer projelerle tutarlı CI-gating deseni), malformed token için exit code 2.
- Durum: ✅ 17/17 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI 6 örnek token'a karşı gerçekten çalıştırıldı ve beklenen bulgular birebir doğrulandı (weak_secret_token.txt → "secret" gerçekten crack edildi, clean_token.txt → 0 bulgu). `sample_report.md` `weak_secret_token.txt` çalıştırmasından gerçek çıktı olarak üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `JWT-Security-Analyzer` adıyla repo aç, git init + push.
