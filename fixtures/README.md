# Test Fixtures

This folder contains two multi-file demo targets for the analyzer.

## Reversible Demo

Path: `fixtures/reversible-password-demo`

- Target parameter: `password`
- Suggested API context: `/api/auth/login`
- Behavior: the frontend wraps `password` into JSON and encrypts it with `CryptoJS.AES.encrypt(...)`
- Expected classification: `potentially-reversible-encryption`

Known sample pair:

- Plaintext password: `P@ssw0rd!`
- JSON payload before AES:
  `{"password":"P@ssw0rd!","ts":1711000000,"device":"web"}`
- Expected ciphertext:
  `IseUY+Vl478iiD7lanbOl+EkNZIqoXlx9pt0+iqsHNqn/gDYxB2Jg7GY98UJjqxHXQhrozujrLbMyH3XmBLiFA==`

## Irreversible Demo

Path: `fixtures/irreversible-password-demo`

- Target parameter: `password`
- Suggested API context: `/api/member/login`
- Behavior: the frontend URL-encodes JSON, Base64-encodes it, then signs it with `HmacSHA256(...)`
- Expected classification: `irreversible-signature-or-digest`

Known sample pair:

- Plaintext password: `P@ssw0rd!`
- Expected ciphertext:
  `4de61a040f0c97c0098090d2ae0ed2b783d8cda051319630e0358c6298aa5aff`

## How To Use

1. Upload all JS files from one demo into the analyzer, or upload the whole folder as a zip.
2. Set `parameter_name=password`.
3. Optionally set the API context shown above.
4. If you want to test webpage URL mode, serve the folder locally:

```bash
cd /Users/zephyr/Security/Develop/js/fixtures
python3 -m http.server 8765
```

Then use:

- `http://127.0.0.1:8765/reversible-password-demo/index.html`
- `http://127.0.0.1:8765/irreversible-password-demo/index.html`

