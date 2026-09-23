from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
import base64, json, uuid, time, re, sqlite3, os, socket, ssl, xml.sax.saxutils as saxutils
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

app = FastAPI(title="OVSE Integration Test Engine", version="0.1.0")

DB = os.path.join(os.path.dirname(__file__), "ovse_tests.db")
EXPECTED_ISSUER = os.getenv("OVSE_EXPECTED_ISSUER", "").strip()

CLAIMS = {
1:"credentialIssuingDate",2:"enrolmentDate",3:"enrolmentNumber",4:"isNRI",
5:"residentImage",6:"residentName",7:"localResidentName",8:"ageAbove18",
9:"ageAbove50",10:"ageAbove60",11:"ageAbove75",12:"dob",13:"gender",
14:"careOf",15:"localCareOf",16:"building",17:"localBuilding",18:"locality",
19:"localLocality",20:"street",21:"localStreet",22:"landmark",23:"localLandmark",
24:"vtc",25:"localVtc",26:"subDistrict",27:"localSubDistrict",28:"district",
29:"localDistrict",30:"state",31:"localState",32:"poName",33:"localPoName",
34:"pincode",35:"address",36:"regionalAddress",37:"mobile",38:"maskedMobile",
39:"email",40:"maskedEmail",42:"Masked Aadhaar"
}

def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS used_jti (jti TEXT PRIMARY KEY, first_seen INTEGER NOT NULL)")
    c.commit()
    return c

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def parse_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain exactly three segments")
    try:
        header = json.loads(b64u_decode(parts[0]))
        payload = json.loads(b64u_decode(parts[1]))
        signature = b64u_decode(parts[2])
    except Exception as e:
        raise ValueError(f"JWT decoding failed: {e}")
    return parts, header, payload, signature

def load_public_key(pem: str):
    if not pem.strip():
        raise ValueError("Public key is required")
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Public key is not an RSA public key")
    return key

def result(tid, category, name, status, message, details=None):
    return {"id":tid,"category":category,"name":name,"status":status,"message":message,"details":details or {}}

def check_uuid(value):
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False

def domain(url):
    p = urlparse(url)
    return p.hostname.lower() if p.hostname else None

def validate_request(jwt: str, public_key_pem: str, client_id: Optional[str]=None,
                     registration_no: Optional[str]=None, expected_issuer: Optional[str]=None,
                     consume_jti: bool=True):
    tests = []
    try:
        parts, header, payload, signature = parse_jwt(jwt)
    except Exception as e:
        return {"valid":False,"header":{},"payload":{},"tests":[
            result("JWT-STRUCT-001","JWT","JWT structure","FAIL",str(e))
        ],"summary":{}}

    tests.append(result("JWT-STRUCT-001","JWT","JWT has three segments","PASS","JWT parsed successfully"))
    alg = header.get("alg")
    typ = header.get("typ")
    tests.append(result("JWT-001","JWT","Algorithm is RS256","PASS" if alg=="RS256" else "FAIL",
                         f"Received {alg!r}; expected 'RS256'"))
    tests.append(result("JWT-002","JWT","Type is JWT","PASS" if typ=="JWT" else "FAIL",
                         f"Received {typ!r}; expected 'JWT'"))

    try:
        key = load_public_key(public_key_pem)
        key.verify(signature, (parts[0]+"."+parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
        sig_ok=True
        msg="RS256 signature verified with supplied public key"
    except Exception as e:
        sig_ok=False
        msg=f"RS256 verification failed: {e}"
    tests.append(result("JWT-003","JWT","RS256 signature verification","PASS" if sig_ok else "FAIL",msg))

    required=["txn","i","lang","sc","pop","ch","m","ac","sa","iss","exp","iat","jti"]
    for f in required:
        tests.append(result(f"PAY-{f}","Payload",f"Required field '{f}' present",
                            "PASS" if f in payload else "FAIL",
                            "Field present" if f in payload else "Required field is missing"))

    txn=payload.get("txn")
    tests.append(result("PAY-TXN-001","Payload","txn is UUID",
                        "PASS" if check_uuid(txn) else "FAIL",
                        "Valid UUID" if check_uuid(txn) else f"Invalid UUID: {txn!r}"))

    tests.append(result("PAY-I-001","Payload","i equals credential",
                        "PASS" if payload.get("i")=="credential" else "FAIL",
                        f"Received {payload.get('i')!r}"))

    lang=str(payload.get("lang",""))
    lang_ok=lang.isdigit() and 1 <= int(lang) <= 23
    tests.append(result("LANG-001","Language","lang is between 1 and 23",
                        "PASS" if lang_ok else "FAIL",f"Received {lang!r}"))

    sc=str(payload.get("sc",""))
    sc_ok=len(sc)==42 and set(sc)<=set("01")
    tests.append(result("BITMAP-001","Bitmap","sc is a 42-bit binary string",
                        "PASS" if sc_ok else "FAIL",f"Length={len(sc)}, allowed characters={'yes' if set(sc)<=set('01') else 'no'}"))

    pop_ok=payload.get("pop") in (0,1)
    tests.append(result("PAY-POP-001","Payload","pop is 0 or 1","PASS" if pop_ok else "FAIL",f"Received {payload.get('pop')!r}"))

    ch=payload.get("ch")
    ch_ok=ch in ("app","web","qr")
    tests.append(result("INV-001","Invocation","ch is app/web/qr","PASS" if ch_ok else "FAIL",f"Received {ch!r}"))

    m=payload.get("m")
    m_ok=str(m) in ("0","1")
    tests.append(result("PAY-M-001","Payload","m is '0' or '1'","PASS" if m_ok else "FAIL",f"Received {m!r}"))

    if client_id:
        tests.append(result("PAY-AC-001","Payload","ac matches submitted Client ID",
                            "PASS" if payload.get("ac")==client_id else "FAIL",
                            f"JWT ac={payload.get('ac')!r}, submitted={client_id!r}"))

    if registration_no:
        tests.append(result("PAY-SA-001","Payload","sa matches submitted registration number",
                            "PASS" if payload.get("sa")==registration_no else "FAIL",
                            f"JWT sa={payload.get('sa')!r}, submitted={registration_no!r}"))

    cb=payload.get("cb")
    aud=payload.get("aud")
    if ch in ("web","qr"):
        https_ok=isinstance(cb,str) and urlparse(cb).scheme=="https" and bool(domain(cb))
        tests.append(result("INV-CB-001","Invocation","cb is HTTPS URL","PASS" if https_ok else "FAIL",
                            f"cb={cb!r}"))
        if aud is not None and https_ok:
            aud_domain=domain(aud) if isinstance(aud,str) else None
            cb_domain=domain(cb)
            tests.append(result("INV-AUD-001","Invocation","aud domain matches cb domain",
                                "PASS" if aud_domain==cb_domain else "FAIL",
                                f"aud domain={aud_domain!r}, cb domain={cb_domain!r}"))
        else:
            tests.append(result("INV-AUD-001","Invocation","aud domain matches cb domain","FAIL",
                                "aud/cb cannot be evaluated"))
    if ch=="app":
        for f in ("aid","asig"):
            present=bool(payload.get(f))
            tests.append(result(f"INV-APP-{f}","Invocation",f"{f} is present for App-to-App",
                                "PASS" if present else "FAIL",f"Received {'present' if present else 'missing'}"))

    iss=payload.get("iss")
    configured_issuer=expected_issuer if expected_issuer is not None else EXPECTED_ISSUER
    if configured_issuer:
        tests.append(result("PAY-ISS-001","Payload","iss matches configured issuer",
                            "PASS" if iss==configured_issuer else "FAIL",
                            f"JWT iss={iss!r}, configured={configured_issuer!r}"))
    else:
        tests.append(result("PAY-ISS-001","Payload","iss configured for validation","WARN",
                            "No expected issuer configured on the test service; value was not judged."))

    now=int(time.time())
    exp=payload.get("exp")
    iat=payload.get("iat")
    exp_ok=isinstance(exp,int) and exp>now
    iat_ok=isinstance(iat,int) and iat<=now+30
    tests.append(result("TIME-001","Security","exp is in the future","PASS" if exp_ok else "FAIL",f"exp={exp!r}, now={now}"))
    tests.append(result("TIME-002","Security","iat is not materially in the future","PASS" if iat_ok else "FAIL",f"iat={iat!r}, now={now}"))
    if isinstance(exp,int) and isinstance(iat,int) and exp>iat:
        lifetime=exp-iat
        tests.append(result("TIME-003","Security","expiry lifetime is short",
                            "PASS" if lifetime<=300 else "WARN",
                            f"Lifetime={lifetime}s; specification recommends 5 minutes"))
    else:
        tests.append(result("TIME-003","Security","expiry lifetime is short","FAIL","exp/iat cannot be evaluated"))

    jti=payload.get("jti")
    jti_ok=check_uuid(jti)
    tests.append(result("SEC-JTI-001","Security","jti is UUID","PASS" if jti_ok else "FAIL",f"jti={jti!r}"))
    replay=False
    if jti_ok and consume_jti:
        c=db()
        try:
            c.execute("INSERT INTO used_jti(jti,first_seen) VALUES(?,?)",(str(jti),now))
            c.commit()
        except sqlite3.IntegrityError:
            replay=True
        finally:
            c.close()
        tests.append(result("SEC-JTI-002","Security","jti has not been used before",
                            "FAIL" if replay else "PASS",
                            "Replay detected" if replay else "jti accepted as new"))
    else:
        tests.append(result("SEC-JTI-002","Security","jti replay check","WARN","Replay check skipped because jti is invalid or disabled"))

    overall = all(t["status"]=="PASS" for t in tests)
    counts={s:sum(1 for t in tests if t["status"]==s) for s in ("PASS","FAIL","WARN")}
    return {"valid":overall,"header":header,"payload":payload,"tests":tests,"summary":counts}

class ValidateRequest(BaseModel):
    jwt: str
    public_key: str
    client_id: Optional[str]=None
    registration_number: Optional[str]=None
    expected_issuer: Optional[str]=None
    consume_jti: bool=True

class CallbackRequest(BaseModel):
    callback_url: str
    txn_id: str = Field(default_factory=lambda:str(uuid.uuid4()))
    credential: Optional[str] = None
    timeout_seconds: int = 10

SAMPLE_SD_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9."
    "eyJpc3MiOiJodHRwczovL3NhbXBsZS51aWRhaS5nb3YuaW4iLCJfc2RfYWxnIjoic2hhLTI1NiIs"
    "InN1YiI6InRlc3QtdXNlciIsIl9zZCI6W119."
    "TEST_SIGNATURE_FOR_CALLBACK_INTEGRATION"
)

@app.get("/api/health")
def health():
    return {"ok":True,"service":"ovse-integration-test-engine","time":datetime.now(timezone.utc).isoformat()}

@app.post("/api/validate-jwt")
def validate_jwt(req: ValidateRequest):
    return validate_request(req.jwt,req.public_key,req.client_id,req.registration_number,req.expected_issuer,req.consume_jti)

def validate_ssl_certificate(host: str, port: int, timeout: int):
    """Perform an independent TLS handshake so SSL/chain failures are reported separately."""
    context = ssl.create_default_context()
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()
                chain_count = None
                # Available on newer Python/OpenSSL builds. The handshake itself already
                # validates the peer chain against the system trust store.
                if hasattr(tls_sock, "get_verified_chain"):
                    try:
                        chain_count = len(tls_sock.get_verified_chain())
                    except Exception:
                        chain_count = None
                not_after = cert.get("notAfter") if cert else None
                expiry = None
                if not_after:
                    expiry = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(not_after), tz=timezone.utc
                    ).isoformat()
                return {
                    "status":"PASS",
                    "message":"TLS certificate and trust chain validated successfully",
                    "hostname":host,
                    "port":port,
                    "tls_version":protocol,
                    "cipher":cipher[0] if cipher else None,
                    "certificate_subject":dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "certificate_issuer":dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "certificate_expires_utc":expiry,
                    "chain_certificates":chain_count,
                    "elapsed_ms":round((time.time()-started)*1000,2)
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "status":"FAIL",
            "message":"TLS certificate chain validation failed",
            "error":str(e),
            "verify_code":getattr(e,"verify_code",None),
            "verify_message":getattr(e,"verify_message",None),
            "elapsed_ms":round((time.time()-started)*1000,2)
        }
    except Exception as e:
        return {
            "status":"FAIL",
            "message":"TLS/SSL connection failed",
            "error":str(e),
            "elapsed_ms":round((time.time()-started)*1000,2)
        }

def callback_test_result(test_id, name, status, message, details=None):
    return result(test_id, "Callback", name, status, message, details)

@app.post("/api/test-callback")
def test_callback(req: CallbackRequest):
    import urllib.request, urllib.error
    p=urlparse(req.callback_url)
    if p.scheme!="https" or not p.hostname:
        raise HTTPException(400,"Callback URL must use HTTPS and contain a valid hostname")
    if not (1 <= req.timeout_seconds <= 30):
        raise HTTPException(400,"timeout_seconds must be between 1 and 30")

    credential = (req.credential or "").strip() or SAMPLE_SD_JWT
    safe_txn = saxutils.escape(req.txn_id)
    safe_credential = saxutils.escape(credential)
    body=f"<Request><TxnID>{safe_txn}</TxnID><Credential>{safe_credential}</Credential></Request>".encode()

    tests=[]
    ssl_result=validate_ssl_certificate(p.hostname, p.port or 443, req.timeout_seconds)
    tests.append(callback_test_result(
        "CB-SSL-001", "SSL certificate and certificate-chain validation",
        ssl_result["status"], ssl_result["message"], ssl_result
    ))

    # The real POST below is the method-support test and the sample SD-JWT transport test.
    request=urllib.request.Request(
        req.callback_url,
        data=body,
        headers={"Content-Type":"application/xml","Accept":"application/xml"},
        method="POST"
    )
    started=time.time()
    try:
        with urllib.request.urlopen(request,timeout=req.timeout_seconds) as response:
            raw=response.read(8192).decode("utf-8","replace")
            elapsed=round((time.time()-started)*1000,2)
            status=response.status
            post_ok=200 <= status < 400
            tests.append(callback_test_result(
                "CB-POST-001", "Callback accepts POST method",
                "PASS" if post_ok else "FAIL",
                f"POST request returned HTTP {status}",
                {"http_status":status,"elapsed_ms":elapsed,"response":raw[:8192]}
            ))
            tests.append(callback_test_result(
                "CB-SDJWT-001", "Sample SD-JWT accepted as Credential",
                "PASS" if post_ok else "FAIL",
                "Sample SD-JWT was sent in the Credential element and the endpoint returned a successful HTTP response" if post_ok else "Sample SD-JWT was sent, but the endpoint did not return a successful HTTP response",
                {"credential_source":"sample default" if not req.credential else "submitted test credential",
                 "credential_sent":True,"http_status":status,"response":raw[:8192]}
            ))
            tests.append(callback_test_result(
                "CB-XML-001", "Callback accepts expected XML payload",
                "PASS" if post_ok else "FAIL",
                "Request XML was sent with TxnID and Credential elements",
                {"content_type":"application/xml","txn_id":req.txn_id}
            ))
            response_data={"http_status":status,"elapsed_ms":elapsed,"response":raw[:8192]}
    except urllib.error.HTTPError as e:
        raw=e.read(8192).decode("utf-8","replace")
        elapsed=round((time.time()-started)*1000,2)
        tests.append(callback_test_result("CB-POST-001","Callback accepts POST method","FAIL",
                                          f"POST request returned HTTP {e.code}",
                                          {"http_status":e.code,"elapsed_ms":elapsed,"response":raw}))
        tests.append(callback_test_result("CB-SDJWT-001","Sample SD-JWT accepted as Credential","FAIL",
                                          "Sample SD-JWT was sent, but the endpoint returned an HTTP error",
                                          {"credential_sent":True,"http_status":e.code,"response":raw}))
        tests.append(callback_test_result("CB-XML-001","Callback accepts expected XML payload","FAIL",
                                          "Callback returned an HTTP error for the XML POST",
                                          {"content_type":"application/xml","txn_id":req.txn_id}))
        response_data={"http_status":e.code,"elapsed_ms":elapsed,"response":raw,"error":"HTTP error"}
    except Exception as e:
        elapsed=round((time.time()-started)*1000,2)
        tests.append(callback_test_result("CB-POST-001","Callback accepts POST method","FAIL",
                                          f"POST request failed: {e}",{"elapsed_ms":elapsed}))
        tests.append(callback_test_result("CB-SDJWT-001","Sample SD-JWT accepted as Credential","FAIL",
                                          f"Could not complete sample SD-JWT callback test: {e}",{"credential_sent":True}))
        tests.append(callback_test_result("CB-XML-001","Callback accepts expected XML payload","FAIL",
                                          f"Could not complete XML callback test: {e}",{"content_type":"application/xml"}))
        response_data={"http_status":None,"elapsed_ms":elapsed,"response":"","error":str(e)}

    counts={s:sum(1 for t in tests if t["status"]==s) for s in ("PASS","FAIL","WARN")}
    overall=all(t["status"]=="PASS" for t in tests)
    return {
        "status":"PASS" if overall else "FAIL",
        "valid":overall,
        "callback_url":req.callback_url,
        "txn_id":req.txn_id,
        "credential_source":"sample default" if not req.credential else "submitted test credential",
        "tests":tests,
        "summary":counts,
        "response":response_data
    }

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__),"static"),html=True), name="static")
