<!--
Thanks for registering with AIDID. Keep it simple: this pull request should change
ONLY `rp-registry.json`. The validation workflow refuses to auto-merge anything else.
-->

## Registering a relying party

**Origin:** <!-- e.g. https://app.example — canonical https origin, no path, no trailing slash -->
**Challenge:** <!-- e.g. aidid-rp-verify-0123456789abcdef0123456789abcdef -->

### Checklist

- [ ] I added (or updated) exactly one entry in `rp-registry.json` and changed nothing else.
- [ ] The entry's `origin` is a plain `https://` origin: no path, no query, no trailing slash, no credentials.
- [ ] The entry's `challenge` matches `^aidid-rp-verify-[0-9a-f]{16,64}$`.
- [ ] `https://<my origin>/.well-known/aidid-rp.txt` serves **exactly** that challenge (surrounding whitespace is fine).
- [ ] I understand a listing only proves control of the origin — it is **not** a security or reputation endorsement by AIDID.

### Proof

Paste the response body from `https://<your origin>/.well-known/aidid-rp.txt`:

```
<!-- paste the file content here -->
```

### Notes

- A `did:msg:…` field is recommended now and required from on-chain phase 1.
- If the challenge check passes and this pull request changes only `rp-registry.json`, it is merged automatically — including when the pull request comes from a fork.
- No invitation or manual review is needed. If you opened this from a fork, the head branch stays in your fork; we cannot delete it for you.
