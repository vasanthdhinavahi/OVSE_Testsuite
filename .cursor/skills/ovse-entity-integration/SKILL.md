---
name: ovse-entity-integration
description: >-
  Guides an OVSE entity that pastes this skill. Asks for their config, tech
  stack, requested claims, and pop. Emits app-to-app, web-to-app, and QR
  code with lang "23" and m "1", plus curl checks for callback TLS, the
  certificate chain, POST, and XML. Diagnoses expired JWTs, RS256 signature
  failures, and claim mismatches. Use when the user pastes an OVSE config,
  asks for integration code, or pastes a failing JWT or validation error.
disable-model-invocation: false
---

# OVSE entity integration

An integrating entity pasted this skill. Specification v3 is the contract. Fill every snippet from their config. Do not use sample ids from the onboarding portal (`000`, `00b1`, or any key already in a repo).

Never ask for, echo, or write the private key. If they paste one, stop, tell them to rotate it, and continue with the public key only. Do not log the JWT or the SD-JWT in the code you emit.

## Start here

Do this before any code.

1. If they pasted a JWT, an error, or a portal test result, go to **Diagnose**. Do not generate a new integration first.
2. Otherwise go to **Generate**. If config or stack is missing, ask, then wait.

Do not ask for a language code or for a single channel. `lang` is always `"23"`. `m` is always `"1"`. Code is always produced for app-to-app, web-to-app, and QR. Do not implement NFC, Bluetooth, BLE, or ISO/IEC 18013-5.

Ask with this, and only for what is still missing:

```
Paste your OVSE config and your tech stack.

Config fields:
- clientId          → JWT ac
- licenseNumber     → JWT sa
- callbackUrl       → JWT cb (https)
- publicKey         → SPKI PEM, BEGIN PUBLIC KEY

Do not paste the private key. Keep it in a secret store.

Tech stack:
- Backend: Node.js, Java, Python, or .NET
- Client: Android, iOS, or Web

Claims to request: names from the bitmap, or "name and masked Aadhaar"

pop is a number, 0 or 1:
- 1 — face verification runs, then the credential is shared
- 0 — face verification is skipped and the credential is shared directly
```

When you ask for `pop`, explain those two outcomes in the message. Wait for their choice. Do not default it.

Accept the config as JSON, as `export const OVSE_CONFIG = { ... }`, or as env vars. Derive `aud` as the origin of `callbackUrl` (scheme + host + port if present). Reject a non-HTTPS `callbackUrl` and a PEM that is not `BEGIN PUBLIC KEY`.

## Generate

Always emit all of the following, with their `clientId`, `licenseNumber`, `callbackUrl`, and derived `aud` already substituted. Use their backend for the signer, callback, and QR encoder. Use their client for the in-app samples, and still include the other platform's launch string so every flow is present.

1. Payload builder and RS256 signer. Private key is read from `OVSE_PRIVATE_KEY_PEM`, never inlined. The signer takes `ch` so the same code serves all three flows.
2. App-to-app launch (`ch` is `"app"`).
3. Web-to-app launch (`ch` is `"web"`).
4. QR encoder (`ch` is `"qr"`).
5. Callback handler.
6. The four callback checks, with their real callback URL filled in.

Shared payload rules:

- Header is exactly `{ "alg": "RS256", "typ": "JWT" }`.
- `txn` and `jti` are new UUID v4 strings per request.
- `i` is `credential`. `iss` is `https://uidai.gov.in`.
- `lang` is the string `"23"`. Do not ask which language, and do not emit any other code.
- `m` is the string `"1"`.
- `pop` is the number they chose. Before the snippet, restate the meaning: `1` runs face verification before the credential is shared; `0` skips face verification and the credential is shared directly.
- `ch` is `"app"`, `"web"`, or `"qr"` on that flow's token. Do not reuse one token across flows.
- `iat` is unix seconds now. `exp` is `iat + 300`. Never milliseconds.
- `sc` is 42 characters of `0` and `1`. Set only the bits they asked for. Bit 41 stays `0`. Bits, from the left: 1 credentialIssuingDate, 2 enrolmentDate, 3 enrolmentNumber, 4 isNRI, 5 residentImage, 6 residentName, 7 localResidentName, 8 ageAbove18, 9 ageAbove50, 10 ageAbove60, 11 ageAbove75, 12 dob, 13 gender, 14 careOf, 15 localCareOf, 16 building, 17 localBuilding, 18 locality, 19 localLocality, 20 street, 21 localStreet, 22 landmark, 23 localLandmark, 24 vtc, 25 localVtc, 26 subDistrict, 27 localSubDistrict, 28 district, 29 localDistrict, 30 state, 31 localState, 32 poName, 33 localPoName, 34 pincode, 35 address, 36 regionalAddress, 37 mobile, 38 maskedMobile, 39 email, 40 maskedEmail, 42 masked Aadhaar (last four).
- `ht` is the profile hint or `null`. For `app`, include `aid` and `asig` (null allowed). For `web` and `qr`, include `cb` and `aud`.
- Sign the ASCII bytes of `base64url(header).base64url(payload)` with RSASSA-PKCS1-v1_5 and SHA-256. Base64url means no `+`, `/`, or `=`.

### Node.js signer

```js
import { createSign, randomUUID } from 'node:crypto';

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = Math.floor(Date.now() / 1000);
const payload = {
  lang: '23', m: '1', pop, /* their number 0 or 1 */
  ch, /* "app" | "web" | "qr" */
  iat: now, exp: now + 300, txn: randomUUID(), jti: randomUUID()
};
const header = b64url({ alg: 'RS256', typ: 'JWT' });
const body = b64url(payload);
const input = `${header}.${body}`;
const signer = createSign('RSA-SHA256');
signer.update(input);
signer.end();
const jwt = `${input}.${signer.sign(process.env.OVSE_PRIVATE_KEY_PEM).toString('base64url')}`;
```

### Java signer

Use `Signature.getInstance("SHA256withRSA")` over the ASCII bytes of `header.payload`. Load the PKCS#8 private key from the environment. Encode header, payload, and signature with a base64url encoder that omits padding.

### Python signer

```python
import time, uuid, jwt  # PyJWT
now = int(time.time())
payload["txn"] = str(uuid.uuid4())
payload["jti"] = str(uuid.uuid4())
payload["lang"] = "23"
payload["m"] = "1"
payload["pop"] = pop  # number 0 or 1
payload["iat"] = now
payload["exp"] = now + 300
token = jwt.encode(payload, os.environ["OVSE_PRIVATE_KEY_PEM"], algorithm="RS256", headers={"typ": "JWT"})
```

Pass `algorithm="RS256"` explicitly.

### .NET signer

Use `RSA.Create()`, `ImportFromPem` on the env var, and `JwtSecurityTokenHandler` with `SecurityAlgorithms.RsaSha256`. Set `iat` and `exp` as `DateTimeOffset` in seconds, lifetime 5 minutes.

### Invocation strings to rewrite

If their code matches any of these, replace it. Do not keep the old string beside the new one.

- Web iOS omits `&source=web`. Keep it. The URL is `pehchaan://in.gov.uidai.pehchan?request=` plus the encoded JWT, then `&source=web`. Host stays `in.gov.uidai.pehchan`. Query name stays `request`.
- Web Android has `S.request=(token)`. `(token)` is six literal characters. Put the JWT variable there.
- App Android omits `` `package` ``, or builds `Intent(INTENT)` from a different constant than the action string. Set the package, and use one action string: `in.gov.uidai.pehchaan.INTENT_REQUEST`. The extra value is the JWT, including when their variable is named `payload.value`.
- App iOS uses host `in.gov.uidai.pehchaan` or query name `req`. Use host `in.gov.uidai.pehchan` and query name `request`, and add `callback`.

Scheme is `pehchaan://`. iOS host is `in.gov.uidai.pehchan` (one `a`). Android package and actions use `in.gov.uidai.pehchaan` (two `a`s).

### Android app-to-app

`ch` is `"app"`.

```kotlin
val intent = Intent("in.gov.uidai.pehchaan.INTENT_REQUEST").apply {
    `package` = "in.gov.uidai.pehchaan"
    putExtra("request", jwt)
}
try {
    startActivity(intent)
} catch (e: ActivityNotFoundException) {
    try {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=in.gov.uidai.pehchaan")))
    } catch (ex: ActivityNotFoundException) {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=in.gov.uidai.pehchaan")))
    }
}
```

### iOS app-to-app

`ch` is `"app"`. `callback` is the invoking app's callback name.

```swift
let customurl = "pehchaan://in.gov.uidai.pehchan?request=\(jwt)&callback=\(callback)"
guard let encodedurl = customurl.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
      let url = URL(string: encodedurl) else { return }
if UIApplication.shared.canOpenURL(url) {
    UIApplication.shared.open(url)
} else if let store = URL(string: "https://apps.apple.com/in/app/aadhaar/id6744029871") {
    UIApplication.shared.open(store)
}
```

### Web

`ch` is `"web"`. On a phone, navigate straight to the intent URL. A desktop browser shows the QR. Do not follow the intent URL with an App Store or Play Store `setTimeout`. Store links, when shown, are separate download badges.

iOS. `request` is `encodeURIComponent(jwt)`, then `&source=web`.

```javascript
if (isMobile() && isIOS()) {
  const encodedRequest = encodeURIComponent(jwt);
  const appUrl = "pehchaan://in.gov.uidai.pehchan?request=" + encodedRequest + "&source=web";
  window.location.href = appUrl;
}
```

Android. `S.request` is the JWT variable. The literal `(token)` is not the JWT.

```javascript
if (isMobile() && android) {
  const url = "intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;S.request=" + jwt + ";end";
  window.location.href = url;
}
```

### QR

`ch` on this token is `"qr"`. Do not reuse the app or web JWT. Emit these functions. The decimal is only the QR `value`. The intent extra stays the JWT.

`gzip.compress` uses its defaults: level 9, the current unix time in the gzip header, and OS byte 255. A compressor that writes OS byte 3, or mtime 0, still inflates, but the base-10 string will not match this Python.

```python
import gzip, qrcode

def jwt_to_iso88591_bytes(jwt_string):
    return jwt_string.encode("ISO-8859-1")

def append_delimiter(data):
    return data + bytes([255])

def compress_data(data):
    return gzip.compress(data)

def byte_array_to_bigint(byte_array):
    return int.from_bytes(byte_array, byteorder="big")

def bigint_to_base10_string(bigint):
    return str(bigint)

def generate_qr_code_value_from_jwt(jwt_string):
    byte_array = jwt_to_iso88591_bytes(jwt_string)
    byte_array_with_delimiter = append_delimiter(byte_array)
    compressed_data = compress_data(byte_array_with_delimiter)
    big_int = byte_array_to_bigint(compressed_data)
    return bigint_to_base10_string(big_int)

qr_code_value = generate_qr_code_value_from_jwt(jwt_token)
qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
qr.add_data(f"https://maadhaar.com/getIntent?value={qr_code_value}")
qr.make(fit=True)
qr.make_image(fill_color="black", back_color="white").save("qrcode.png")
```

Do not copy the sample payload that often ships next to this pipeline. Keep the functions. Fix the claims: `exp` is `iat + 300` (the sample's `iat + 30` is 30 seconds, not minutes). `iss` is `https://uidai.gov.in`. `aud` is the origin of `cb`. New `txn` and `jti` every request. Bit 41 of `sc` stays `0`. Do not print the JWT.

### Callback checks

After the handler, give these commands with their `callbackUrl` substituted. Say what a pass looks like under each one.

Certificate chain and hostname. Pass when the output ends with `Verify return code: 0 (ok)` and `showcerts` prints the leaf plus at least one issuer certificate. One certificate means the chain is incomplete.

```bash
openssl s_client -connect HOST:PORT -servername HOST -showcerts </dev/null
```

TLS trust from a client. Pass when `ssl_verify_result` is `0`. Any other value is an untrusted chain, a hostname mismatch, or an expired certificate.

```bash
curl -sS -o /dev/null -w "ssl_verify=%{ssl_verify_result}\n" --connect-timeout 10 "https://HOST/"
```

POST is accepted. Pass when the status is not `405`, `301`, or `302`. Do not add `-L`. A redirect often drops the XML body.

XML is accepted. Pass when the body is XML, `TxnID` equals the value you sent, `ResponseCode` is `200`, and `ResponseMsg` is `Success`. An HTML body, `415`, or a parser error means the endpoint is not accepting this XML.

```bash
curl -sS -D - -X POST "CALLBACK_URL" \
  -H "Content-Type: application/xml" \
  -H "Accept: application/xml" \
  --data-binary '<?xml version="1.0" encoding="UTF-8"?>
<Request>
  <TxnID>00000000-0000-4000-8000-000000000001</TxnID>
  <Credential>probe</Credential>
</Request>'
```

### Callback

The Aadhaar App POSTs:

```xml
<Request>
  <TxnID>TXN_ID</TxnID>
  <Credential>SD-JWT</Credential>
</Request>
```

Reply with the same `TxnID`. Success is `ResponseCode` `200` and `ResponseMsg` `Success`. The `Credential` is `header.payload.signature~disclosure~...`. Verify that issuer JWT with the **UIDAI** public key, not the entity key in config. SHA-256 each disclosure, base64url the digest, and require it in `_sd`. Then acknowledge.

## Diagnose

Decode the JWT they pasted (header and payload only). Compare claims to their config. Name one primary failure, then the other failures. Do not say "invalid JWT" without the failing field.

### Expired

`exp` is unix seconds. It has expired when `exp` is less than or equal to now.

- Say the UTC time of `exp` and of now, and tell them to sign a new token with `exp = iat + 300`.
- A 13-digit `exp` or `iat` is milliseconds. That token is already expired or far in the future. Use seconds.
- `exp` less than or equal to `iat` fails even when `exp` is still in the future.
- An expired token cannot be fixed by editing the payload. That breaks the signature. Sign again.

### Signature verification failed

Check in this order and stop at the first match:

1. `alg` is not `RS256` (often `HS256`, `RS512`, or `none`).
2. The token does not have three base64url segments, or it picked up whitespace or a newline when pasted.
3. The verifier is using a different public key than the one registered. Compare the SPKI they registered with the key in config.
4. The PEM is `BEGIN CERTIFICATE`, `BEGIN RSA PUBLIC KEY`, or a private key. Verification of the intent JWT wants `BEGIN PUBLIC KEY`.
5. They signed a re-serialized payload (different key order or spaces) instead of the exact `header.payload` bytes.
6. The signature is standard base64 (`+`, `/`, `=`) rather than base64url.
7. They verified the **SD-JWT** with the entity public key. The intent JWT uses the entity key. The credential in the callback uses the UIDAI key.

### Parameter issues

| What they see | Cause | Fix |
| --- | --- | --- |
| `txn` or `jti` must be a UUID | Not UUID v1–v5, or reused | New UUID per request. Reject a replay. |
| `i` must be credential | Any other string | Set `i` to `credential`. |
| `lang` must be numeric | Missing, or any code other than 23 | Set `lang` to the string `"23"`. |
| `pop` must be 0 or 1 | Missing, a string, or another number | JSON number `0` or `1`. `1` runs face verification, then the credential is shared. `0` skips face verification and the credential is shared directly. |
| `sc` length is not 42 | 64 bits, or the 43-character spec sample | Build 42 bits. Leave bit 41 as `0`. |
| `ch` is required | Empty, or one token reused for every flow | `"app"`, `"web"`, or `"qr"` on the matching flow. |
| Pehchaan does not open | Wrong host, query name, or extra | Web iOS: `pehchaan://in.gov.uidai.pehchan?request=` plus the encoded JWT, then `&source=web`. Web Android: `S.request` is the JWT, not the literal `(token)`. App iOS: host `in.gov.uidai.pehchan`, query `request`, plus `callback`. App Android: set `` `package` `` to `in.gov.uidai.pehchaan` and put the JWT in `request`. |
| `m` is required | Missing, or the number `1` | The string `"1"`. |
| `ac` expected `<clientId>` | Claim does not match config | Set `ac` to `clientId`, no extra spaces. |
| `sa` expected `<licenseNumber>` | Claim does not match config | Set `sa` to `licenseNumber`. |
| `cb` expected `<callbackUrl>` | Different URL | `cb` must equal `callbackUrl` character for character: scheme, host, port, path, no extra slash. |
| `aud` is required | Empty, or the full callback path | `aud` is the origin of `cb` only. |
| `iss` expected `https://uidai.gov.in` | Another issuer | Set `iss` to that exact URL. |
| `iat` must be a positive timestamp | Missing, or a date string | Unix seconds. |
| HTTP not ok, XML invalid, TxnID mismatch, `ResponseCode` not `200`, `ResponseMsg` not `Success` | Callback contract | Echo `TxnID`. Success text is exactly `Success`. |
| Response code `301`–`308` | Aadhaar App failure, not a bad claim | `301` user rejected, `302` liveness failed after 3 tries, `303` user aborted, `304` face mismatch, `305` biometric locked, `306` FaceRD down, `307` network, `308` auth succeeded but callback delivery failed (retry). |

If several rows match, list them. Lead with expiry or signature when those are the ones the portal marked failed.
