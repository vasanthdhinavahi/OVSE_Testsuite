# OVSE Technical Onboarding Portal

## Run

```bash
npm install
npm run dev
```

No Python runtime is required. QR generation is implemented entirely in React using `pako` and `qrcode`.

## Configure

Edit `src/config.js` with the registered Client ID, License Number, Callback URL, and submitted RSA public key.

## Flow

JWT Reference → Validate Request → Invocation & QR → Callback Testing

## Callback contract

The portal sends:

```xml
<Request>
  <TxnID>TXN_ID</TxnID>
  <Credential>CREDENTIAL</Credential>
</Request>
```

The callback endpoint is expected to return:

```xml
<Response>
  <TxnID>TXN_ID</TxnID>
  <ResponseCode>200</ResponseCode>
  <ResponseMsg>Success</ResponseMsg>
</Response>
```

The portal validates HTTP success, XML validity, matching TxnID, ResponseCode `200`, and ResponseMsg `Success`.
