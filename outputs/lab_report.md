# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-28T04:52:04.438694+00:00`
- Framework: `google-adk`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/5`
- Attack queries blocked: `7/7`
- Edge cases blocked: `3/3`
- Rate limit blocked/sent: `5/15`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.5-flash`
- Unsafe leaks (Red): `5/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m                                                               [100%][0m
[32m[32m[1m10 passed[0m[32m in 3.41s[0m[0m
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
