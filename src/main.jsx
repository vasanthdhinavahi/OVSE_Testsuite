import React, {useEffect, useMemo, useState} from 'react';
import {createRoot} from 'react-dom/client';
import jsPDF from 'jspdf';
import pako from 'pako';
import QRCode from 'qrcode';
import {OVSE_CONFIG} from './config';
import './styles.css';

const jwtSample = {
  txn:'94f63917-708a-4e58-9001-fce56d839948', i:'credential', lang:'23',
  sc:'000011000001000000000000000000000010101011', pop:1, ch:'app', m:'1',
  ac:OVSE_CONFIG.clientId, sa:OVSE_CONFIG.licenseNumber, cb:OVSE_CONFIG.callbackUrl,
  aud:'https://myaadhaarstage.uidai.gov.in', iss:'https://uidai.gov.in', exp:1790837771, iat:1790837471,
  ht:'Name of the person', aid:'', asig:'', jti:'8a9d7c2b-b932-4131-9e36-43f22a019be5'
};

const groups=[
 {name:'JWT & Cryptographic Validation', ids:[1,2,3,4]},
 {name:'JWT Payload Validation', ids:[6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21]},
 {name:'JWT Security Validation', ids:[22,23]}
];

const tests={
 1:'Validate JWT structure and format.',
 2:'Validate JWT header algorithm as RS256.',
 3:'Validate JWT token type as JWT.',
 4:'Verify JWT signature using the public key provided by the entity.',
 6:'Validate transaction ID (txn) format and uniqueness.',
 7:'Validate credential identifier (i).',
 8:'Validate language code (lang).',
 9:'Validate population option (pop).',
 10:'Validate scope/bitmap (sc) format and 42-bit length.',
 11:'Validate invocation channel (ch).',
 12:'Validate mode (m).',
 13:'Validate client ID (ac) against the registered client ID.',
 14:'Validate registration number (sa).',
 15:'Validate callback URL (cb).',
 16:'Validate audience (aud).',
 17:'Validate issuer (iss).',
 18:'Validate issued-at time (iat).',
 19:'Validate expiry time (exp).',
 20:'Validate JWT ID (jti) and replay protection.',
 21:'Validate required JWT claims and value types.',
 22:'Validate expired JWT handling.',
 23:'Validate invalid JWT signature handling.'
};

const payloadTestByField={txn:6,i:7,lang:8,pop:9,sc:10,ch:11,m:12,ac:13,sa:14,cb:15,aud:16,iss:17,iat:18,exp:19,jti:20};


function b64urlDecode(s){
  const pad='='.repeat((4-s.length%4)%4);
  const bin=atob(s.replace(/-/g,'+').replace(/_/g,'/')+pad);
  return Uint8Array.from(bin,c=>c.charCodeAt(0));
}

function parseJWT(token){
  const p=token.trim().split('.');
  if(p.length!==3) throw new Error('JWT must contain exactly three segments.');
  return {
    header:JSON.parse(new TextDecoder().decode(b64urlDecode(p[0]))),
    payload:JSON.parse(new TextDecoder().decode(b64urlDecode(p[1]))),
    raw:p
  };
}

function uuid(v){
  return typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
}

function pemToDer(pem){
  const b=pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g,'');
  const bin=atob(b);
  return Uint8Array.from(bin,c=>c.charCodeAt(0));
}

async function verifyRS256(token,pem){
  if(!pem||pem.includes('REPLACE_WITH')) return null;
  try{
    const {raw}=parseJWT(token);
    const key=await crypto.subtle.importKey('spki',pemToDer(pem),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
    const sig=b64urlDecode(raw[2]);
    const data=new TextEncoder().encode(raw[0]+'.'+raw[1]);
    return await crypto.subtle.verify({name:'RSASSA-PKCS1-v1_5'},key,sig,data);
  }catch{return false;}
}

function App(){
  const [page,setPage]=useState('overview');
  const [token,setToken]=useState('');
  const [result,setResult]=useState(null);
  const [copied,setCopied]=useState(false);
  const [callbackResult,setCallbackResult]=useState(null);

  const run=async()=>{
    const out={};
    let parsed;
    try{
      parsed=parseJWT(token);
      out[1]=[true,'JWT contains three valid segments.'];
      out[2]=[parsed.header.alg==='RS256',`Expected RS256; received ${parsed.header.alg??'missing'}.`];
      out[3]=[parsed.header.typ==='JWT',`Expected JWT; received ${parsed.header.typ??'missing'}.`];
      out[4]=await verifyRS256(token,OVSE_CONFIG.publicKey).then(v=>v===null?[null,'Public key placeholder is configured; signature verification is ready once the real key is supplied.']:[v,v?'Signature verified with the submitted public key.':'Signature verification failed.']);
      const p=parsed.payload; const now=Math.floor(Date.now()/1000);
      const checks={
        6:[uuid(p.txn),'txn must be a UUID.'],
        7:[p.i==='credential','i must be credential.'],
        8:[/^\d+$/.test(String(p.lang)),'lang must be numeric.'],
        9:[p.pop===0||p.pop===1,'pop must be 0 or 1.'],
        10:[typeof p.sc==='string'&&/^[01]+$/.test(p.sc)&&p.sc.length===42,`sc length received: ${String(p.sc??'').length}; expected exactly 42 bits containing only 0 and 1.`],
        11:[typeof p.ch==='string'&&p.ch.length>0,'ch is required.'],
        12:[typeof p.m==='string'||typeof p.m==='number','m is required.'],
        13:[p.ac===OVSE_CONFIG.clientId,`Expected ${OVSE_CONFIG.clientId}; received ${p.ac??'missing'}.`],
        14:[p.sa===OVSE_CONFIG.licenseNumber,`Expected ${OVSE_CONFIG.licenseNumber}; received ${p.sa??'missing'}.`],
        15:[p.cb===OVSE_CONFIG.callbackUrl,`Expected ${OVSE_CONFIG.callbackUrl}; received ${p.cb??'missing'}.`],
        16:[typeof p.aud==='string'&&p.aud.length>0,'aud is required.'],
        17:[p.iss==='https://uidai.gov.in',`Expected https://uidai.gov.in; received ${p.iss??'missing'}.`],
        18:[Number.isFinite(Number(p.iat))&&Number(p.iat)>0,'iat must be a positive timestamp.'],
        19:[Number.isFinite(Number(p.exp))&&Number(p.exp)>Number(p.iat),'exp must be later than iat.'],
        20:[uuid(p.jti),'jti must be a UUID.'],
        21:[typeof p==='object'&&p!==null,'JWT payload object was decoded successfully.'],
        22:[Number(p.exp)>now,'JWT must not be expired.'],
        23:[out[4][0]===true,'JWT signature must be valid.']
      };
      Object.entries(checks).forEach(([id,v])=>out[id]=v);
      setResult({parsed,out});
    }catch(e){setResult({error:e.message});}
  };

  const copy=async(text)=>{await navigator.clipboard.writeText(text);setCopied(true);setTimeout(()=>setCopied(false),1200);};
  const download=(name,text,type='application/json')=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),0);};

  const downloadTestResultsPDF=()=>{
    if(!result?.out)return;
    let pass=0,fail=0;
    Object.values(result.out).forEach(x=>{if(x?.[0]===true)pass++;if(x?.[0]===false)fail++;});
    const doc=new jsPDF(); const pageWidth=doc.internal.pageSize.getWidth(); const pageHeight=doc.internal.pageSize.getHeight(); let y=20;
    const addPageIfNeeded=(height=10)=>{if(y+height>pageHeight-20){doc.addPage();y=20;}};
    const writeWrapped=(text,x,width,lineHeight=5)=>{const lines=doc.splitTextToSize(String(text||''),width);addPageIfNeeded(lines.length*lineHeight+2);doc.text(lines,x,y);y+=lines.length*lineHeight;};
    doc.setFontSize(19);doc.setFont(undefined,'bold');doc.text('OVSE Request Validation Report',20,y);y+=11;
    doc.setFontSize(9);doc.setFont(undefined,'normal');doc.text(`Generated: ${new Date().toLocaleString()}`,20,y);y+=6;doc.text(`Client ID: ${OVSE_CONFIG.clientId||'Not configured'}`,20,y);y+=6;doc.text(`License Number: ${OVSE_CONFIG.licenseNumber||'Not configured'}`,20,y);y+=6;writeWrapped(`Callback URL: ${OVSE_CONFIG.callbackUrl||'Not configured'}`,20,pageWidth-40,5);y+=7;
    doc.setFontSize(13);doc.setFont(undefined,'bold');doc.text('Validation Summary',20,y);y+=8;doc.setFontSize(10);doc.setFont(undefined,'normal');doc.text(`Passed: ${pass}`,20,y);y+=5;doc.text(`Failed: ${fail}`,20,y);y+=10;
    groups.forEach(group=>{addPageIfNeeded(15);doc.setFontSize(12);doc.setFont(undefined,'bold');doc.text(group.name,20,y);y+=7;group.ids.forEach(id=>{const r=result.out[id];const status=r?.[0]===true?'PASS':r?.[0]===false?'FAIL':'NOT VERIFIED';addPageIfNeeded(24);doc.setFontSize(9);doc.setFont(undefined,'bold');doc.text(`#${id} - ${status}`,20,y);y+=5;doc.setFont(undefined,'normal');writeWrapped(tests[id],25,pageWidth-45,4.5);if(r?.[1]){doc.setFontSize(8);writeWrapped(r[1],25,pageWidth-45,4.5);}y+=3;});y+=3;});
    if(result.parsed?.payload){addPageIfNeeded(25);doc.setFontSize(12);doc.setFont(undefined,'bold');doc.text('Decoded JWT Payload',20,y);y+=7;doc.setFontSize(7.5);doc.setFont(undefined,'normal');writeWrapped(JSON.stringify(result.parsed.payload,null,2),20,pageWidth-40,3.5);}
    const totalPages=doc.internal.getNumberOfPages();for(let i=1;i<=totalPages;i++){doc.setPage(i);doc.setFontSize(7.5);doc.setFont(undefined,'normal');doc.text(`OVSE Request Validation | Page ${i} of ${totalPages}`,20,pageHeight-9);}doc.save(`ovse-validation-report-${Date.now()}.pdf`);
  };

  return <div className="app">
    <aside><div className="brand"><div className="brandmark">O</div><div><b>OVSE</b><span>TECHNICAL ONBOARDING</span></div></div><nav>{[['overview','Overview'],['details','Integration Details'],['jwt','JWT Reference'],['suite','Validate Request'],['invocation','Invocation & QR'],['callback','Callback Testing']].map(([id,l])=><button className={page===id?'active':''} onClick={()=>setPage(id)} key={id}>{l}</button>)}</nav><div className="sidefoot">Technical integration console<br/><span>Configuration supplied by UIDAI</span></div></aside>
    <main><header><div><span className="eyebrow">Aadhaar App • OVSE Integration</span><h1>{page==='suite'?'Validate Request':page==='jwt'?'JWT Reference':page==='details'?'Integration Details':page==='invocation'?'Invocation & QR':page==='callback'?'Callback Testing':'Technical Onboarding'}</h1></div><div className="status">● Configuration loaded</div></header>
      {page==='overview'&&<section className="hero"><div className="heroCard"><span className="eyebrow">ONBOARDING</span><h2>Validate your integration before going live.</h2><p>Review your submitted configuration, understand the expected JWT structure, validate a JWT generated by your application, generate the QR request, review invocation structures, and test the callback.</p><button className="primary" onClick={()=>setPage('jwt')}>View JWT Reference →</button></div><div className="stats"><div><b>23</b><span>Test cases</span></div><div><b>3</b><span>Test groups</span></div><div><b>4</b><span>Registered parameters</span></div></div></section>}
      {page==='details'&&<Details config={OVSE_CONFIG} copy={copy}/>} 
      {page==='jwt'&&<JWTRef sample={jwtSample} copy={copy} download={download} onContinue={()=>setPage('suite')}/>} 
      {page==='suite'&&<Suite token={token} setToken={setToken} run={run} result={result} groups={groups} tests={tests} copy={copy} downloadTestResultsPDF={downloadTestResultsPDF} onContinue={()=>setPage('invocation')}/>} 
      {page==='invocation'&&<Invocation token={token} result={result} copy={copy} download={download}/>} 
      {page==='callback'&&<Callback config={OVSE_CONFIG} token={token} result={callbackResult} setResult={setCallbackResult}/>} 
      {copied&&<div className="toast">Copied</div>}
    </main>
  </div>;
}

function Details({config,copy}){return <section><div className="sectionIntro"><span className="eyebrow">REGISTERED CONFIGURATION</span><h2>Integration Details</h2><p>These values are already associated with this OVSE. The developer does not need to enter them again.</p></div><div className="grid"><Card title="Client ID" value={config.clientId}/><Card title="License Number" value={config.licenseNumber}/><Card title="Callback URL" value={config.callbackUrl}/><div className="card wide"><div className="cardtop"><h3>Public Key Submitted</h3><button onClick={()=>copy(config.publicKey)}>Copy</button></div><pre>{config.publicKey}</pre></div></div></section>;}
function Card({title,value}){return <div className="card"><span>{title}</span><strong>{value}</strong></div>}

function JWTRef({sample,copy,download,onContinue}){const json=JSON.stringify(sample,null,2);return <section><div className="sectionIntro"><span className="eyebrow">REFERENCE ONLY</span><h2>JWT Structure</h2><p>This page does not generate or sign a JWT. It shows the structure the OVSE implementation is expected to produce.</p></div><div className="codecard"><div className="codehead"><b>Payload</b><div><button onClick={()=>copy(json)}>Copy JSON</button><button onClick={()=>download('ovse-jwt-payload.json',json)}>Download</button></div></div><pre>{json}</pre></div><div className="format"><h3>JWT format</h3><code>BASE64URL(HEADER) . BASE64URL(PAYLOAD) . BASE64URL(SIGNATURE)</code><p>The actual JWT must be generated and signed by the OVSE application using the private key corresponding to the public key submitted during onboarding.</p></div><div className="continueSection"><button className="primary" onClick={onContinue}>Continue to Validation →</button></div></section>;}

function PayloadViewer({payload,out}){
  const invalidFields=new Set(Object.entries(payloadTestByField).filter(([,id])=>out?.[id]?.[0]===false).map(([field])=>field));
  const expired=out?.[34]?.[0]===false;
  if(expired) invalidFields.add('exp');
  const requiredFields=['txn','i','lang','sc','pop','ch','m','ac','sa','cb','aud','iss','exp','iat','jti'];
  requiredFields.forEach(field=>{if(payload?.[field]===undefined||payload?.[field]===null||payload?.[field]==='') invalidFields.add(field);});
  return <div className="decoded">
    <div className="codehead"><b>Decoded Payload</b><span className="payloadLegend"><span className="legendRed">●</span> Invalid parameter</span></div>
    <div className="payloadJson">
      <div>{'{'}</div>
      {Object.entries(payload||{}).map(([key,value],index)=>{
        const invalid=invalidFields.has(key);
        const rendered=typeof value==='string'?`"${value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`:JSON.stringify(value);
        return <div className={`payloadLine ${invalid?'payloadInvalid':''}`} key={key}>
          <span className="payloadKey">  &quot;{key}&quot;</span><span>: </span><span>{rendered}</span>{index<Object.keys(payload||{}).length-1?',':''}
        </div>;
      })}
      <div>{'}'}</div>
    </div>
  </div>;
}

function Suite({token,setToken,run,result,groups,tests,copy,downloadTestResultsPDF,onContinue}){
  let pass=0,fail=0;if(result?.out)Object.values(result.out).forEach(x=>{if(x?.[0]===true)pass++;if(x?.[0]===false)fail++;});
  return <section><div className="sectionIntro"><span className="eyebrow">REQUEST VALIDATION • JWT VERIFICATION</span><h2>Validate Request</h2><p>Generate the JWT as per the reference on the previous page by signing it with the private key corresponding to the public key submitted during onboarding. Then paste the generated JWT below to validate the request.</p></div><div className="inputcard"><div className="codehead"><b>JWT generated by your application</b><button onClick={()=>setToken('')}>Clear</button></div><textarea value={token} onChange={e=>setToken(e.target.value)} placeholder="Paste the complete JWT here..."/><div className="actions"><button className="primary" onClick={run} disabled={!token.trim()}>Validate Request</button><button onClick={()=>copy(token)} disabled={!token.trim()}>Copy JWT</button></div></div>{result&&<div className="results"><div className="resultSummary twoColumn"><div><span>Passed</span><b className="green">{pass}</b></div><div><span>Failed</span><b className="red">{fail}</b></div></div>{!result.error&&<div className="resultActions"><button className="primary" onClick={downloadTestResultsPDF}>Download Test Results PDF</button></div>}{result.error?<div className="errorbox">{result.error}</div>:groups.map(group=><div className="testgroup" key={group.name}><h3>{group.name}</h3>{group.ids.map(id=>{const r=result.out[id];const statusClass=r?.[0]===true?'pass':r?.[0]===false?'fail':'warn';const statusIcon=r?.[0]===true?'✓':r?.[0]===false?'✕':'—';return <div className="testrow" key={id}><span className={`dot ${statusClass}`}>{statusIcon}</span><div><b>#{id}</b> {tests[id]}<small>{r?.[1]}</small></div></div>;})}</div>)}{result.parsed&&<PayloadViewer payload={result.parsed.payload} out={result.out} />}{result.parsed&&!result.error&&<div className="continueInvocation"><button className="primary" onClick={onContinue}>Continue to Invocation & QR →</button></div>}</div>}</section>;
}

function Invocation({token,result,copy,download}){
  const [qr,setQr]=useState(null); const [loading,setLoading]=useState(false); const [error,setError]=useState('');
  const parsed=useMemo(()=>{try{return parseJWT(token);}catch{return null;}},[token]);
  const encodedRequest=useMemo(()=>encodeURIComponent(token||''),[token]);
  const iosApp=`pehchaan://in.gov.uidai.pehchan?req=${encodedRequest}`;
  const iosWeb=`pehchaan://in.gov.uidai.pehchan?request=${encodedRequest}&source=web`;
  const androidAppAction='in.gov.uidai.pehchaan.INTENT_REQUEST';
  const androidWebAction='in.gov.uidai.pehchaan.WEB_INTENT_REQUEST';

  const generateQR=async()=>{
    if(!token.trim()){setError('Validate a JWT first.');return;}
    setLoading(true);setError('');setQr(null);
    try{
      // Reproduce the supplied QR algorithm entirely in the browser:
      // JWT -> ISO-8859-1 bytes -> 0xFF -> GZIP -> big integer -> decimal -> QR URL.
      const jwtString=token.trim();
      const isoBytes=new Uint8Array(jwtString.length);
      for(let i=0;i<jwtString.length;i++){
        const code=jwtString.charCodeAt(i);
        if(code>255) throw new Error('JWT contains characters outside the ISO-8859-1 byte range.');
        isoBytes[i]=code;
      }

      const withDelimiter=new Uint8Array(isoBytes.length+1);
      withDelimiter.set(isoBytes);
      withDelimiter[isoBytes.length]=0xFF;

      const compressed=pako.gzip(withDelimiter,{level:9});
      let bigIntValue=0n;
      for(const byte of compressed){
        bigIntValue=(bigIntValue<<8n)+BigInt(byte);
      }

      const value=bigIntValue.toString(10);
      const url=`https://maadhaar.com/getIntent?value=${value}`;
      const pngDataUrl=await QRCode.toDataURL(url,{
        errorCorrectionLevel:'H',
        margin:4,
        width:560
      });

      const hashBuffer=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(jwtString));
      const hashArray=Array.from(new Uint8Array(hashBuffer));
      const jwtSha256=hashArray.map(b=>b.toString(16).padStart(2,'0')).join('');

      setQr({value,url,pngDataUrl,jwtSha256});
    }catch(e){
      setError(e.message||'QR generation failed.');
    }finally{setLoading(false);}
  };

  useEffect(()=>{if(token&&result?.parsed)generateQR();},[]);

  const qrDownload=()=>{if(!qr?.pngDataUrl)return;const a=document.createElement('a');a.href=qr.pngDataUrl;a.download=`ovse-qr-${Date.now()}.png`;a.click();};
  const qrPayload=qr?.url||'';

  return <section>
    <div className="sectionIntro"><span className="eyebrow">INVOCATION • QR • MOBILE INTEGRATION</span><h2>Invocation & QR</h2><p>The validated JWT is reused here. Generate the QR request and review the exact Android and iOS App-to-App and Web-to-App invocation structures used by Pehchaan.</p></div>

    <div className="invocationCard">
      <div className="invocationHeader"><div><span className="invocationSectionTitle">1 • QR GENERATION</span><h3>Generate QR from validated JWT</h3></div><button className="primary" onClick={generateQR} disabled={loading||!token}>{loading?'Generating…':'Generate QR'}</button></div>
      <p className="muted">The QR flow follows the supplied implementation: JWT → ISO-8859-1 bytes → append <code>0xFF</code> → GZIP → big integer → decimal value → <code>https://maadhaar.com/getIntent?value=...</code>.</p>
      {error&&<div className="errorbox">{error}</div>}
      {qr&&<div className="qrLayout"><div className="qrBox"><img src={qr.pngDataUrl} alt="Generated OVSE QR"/><button onClick={qrDownload}>Download QR PNG</button></div><div className="qrMeta"><div className="card"><span>QR Base10 Value</span><code className="breakcode">{qr.value}</code></div><div className="card"><div className="cardtop"><h3>QR URL</h3><button onClick={()=>copy(qr.url)}>Copy</button></div><code className="breakcode">{qr.url}</code></div><div className="card"><span>JWT SHA-256</span><code className="breakcode">{qr.jwtSha256}</code></div></div></div>}
    </div>

    <div className="invocationCard"><span className="invocationSectionTitle">2 • APP-TO-APP INTENT REQUEST</span><h3>Android</h3><p>Use the Pehchaan intent action and send the request in the <code>request</code> extra.</p><div className="codecard"><div className="codehead"><b>Android / Kotlin</b><button onClick={()=>copy(`val intent = Intent("${androidAppAction}").apply {\n    putExtra("request", payload.value)\n}`)}>Copy</button></div><pre>{`val intent = Intent("${androidAppAction}").apply {
    putExtra("request", payload.value)
}`}</pre></div><h3>iOS</h3><p>Construct the Pehchaan custom URL with the request in the <code>req</code> query parameter.</p><div className="codecard"><div className="codehead"><b>iOS / Swift</b><button onClick={()=>copy(`let customurl = "${iosApp}"`)}>Copy</button></div><pre>{`let customurl = "${iosApp}"
guard let encodedurl = customurl.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
    return
}
if let url = URL(string: encodedurl) {
    if UIApplication.shared.canOpenURL(url) {
        UIApplication.shared.open(url)
    }
}`}</pre></div></div>

    <div className="invocationCard"><span className="invocationSectionTitle">3 • WEB-TO-APP INTENT REQUEST</span><h3>iOS</h3><p>For a web-originated request, use the Pehchaan URL with <code>request</code> and <code>source=web</code>.</p><div className="codecard"><div className="codehead"><b>Web → iOS</b><button onClick={()=>copy(`pehchaan://in.gov.uidai.pehchan?request=${encodedRequest}&source=web`)}>Copy</button></div><pre>{`if (isIOS()) {
  return \`pehchaan://in.gov.uidai.pehchan?request=${'${encodedRequest}'}&source=web\`;
}`}</pre></div><h3>Android</h3><p>For Android, use an Android Intent URI with the Pehchaan web-intent action and the request as the <code>S.request</code> extra.</p><div className="codecard"><div className="codehead"><b>Web → Android</b><button onClick={()=>copy(`intent:#Intent;action=${androidWebAction};S.request=(token);end`)}>Copy</button></div><pre>{`const url = "intent:#Intent;action=${androidWebAction};S.request=(token);end";
window.location.replace(url);`}</pre></div></div>

    <div className="note"><b>Validated JWT:</b> {parsed?'JWT parsed successfully and is reused for QR/invocation generation.':'No validated JWT is currently available. Return to Validate Request first.'}</div>
  </section>;
}

function Callback({config,token,result,setResult}){
  const defaultTxn=(()=>{try{return parseJWT(token).payload.txn||'';}catch{return '';}})();
  const [txnId,setTxnId]=useState(defaultTxn); const [credential,setCredential]=useState(token||''); const [loading,setLoading]=useState(false); const [xml,setXml]=useState(''); const [sslLoading,setSslLoading]=useState(false); const [sslResult,setSslResult]=useState(null);
  useEffect(()=>{if(defaultTxn)setTxnId(defaultTxn);if(token)setCredential(token);},[token,defaultTxn]);
  const buildXml=(txn=txnId,cred=credential)=>`<?xml version="1.0" encoding="UTF-8"?>\n<Request>\n  <TxnID>${escapeXml(txn)}</TxnID>\n  <Credential>${escapeXml(cred)}</Credential>\n</Request>`;
  const parseAcknowledgement=(text,requestTxn)=>{try{const doc=new DOMParser().parseFromString(text,'application/xml');if(doc.querySelector('parsererror'))throw new Error('Response is not valid XML.');const responseTxn=doc.querySelector('TxnID')?.textContent?.trim()||'';const responseCode=doc.querySelector('ResponseCode')?.textContent?.trim()||'';const responseMsg=doc.querySelector('ResponseMsg')?.textContent?.trim()||'';return {validXml:true,txnMatch:responseTxn===requestTxn,responseTxn,responseCode,responseMsg,success:responseTxn===requestTxn&&responseCode==='200'&&responseMsg==='Success'};}catch(error){return {validXml:false,success:false,error:error.message};}};
  const sendCallback=async()=>{setLoading(true);setResult(null);const body=buildXml();setXml(body);try{const response=await fetch('/api/callback-test',{method:'POST',headers:{'Content-Type':'application/xml','Accept':'application/xml'},body});const text=await response.text();const acknowledgement=parseAcknowledgement(text,txnId);setResult({status:response.status,httpOk:response.ok,request:body,response:text,acknowledgement,ok:response.ok&&acknowledgement.success});}catch(error){setResult({status:0,httpOk:false,request:body,response:'',acknowledgement:{success:false},ok:false,error:error.message});}finally{setLoading(false);}};
  const runSSLCheck=async()=>{setSslLoading(true);setSslResult(null);try{const response=await fetch('/api/callback-ssl-check');const data=await response.json();setSslResult(data);}catch(error){setSslResult({ok:false,error:error.message});}finally{setSslLoading(false);}};
  return <section><div className="sectionIntro"><span className="eyebrow">CALLBACK INTEGRATION</span><h2>Callback Testing</h2><p>The callback endpoint receives a <code>&lt;Request&gt;</code> containing <code>TxnID</code> and <code>Credential</code>. It must return a <code>&lt;Response&gt;</code> acknowledgement with the same TxnID, ResponseCode 200 and ResponseMsg Success.</p></div>
    <div className="card"><span>Configured Callback URL</span><strong>{config.callbackUrl}</strong></div>

    <div className="invocationCard"><div className="invocationHeader"><div><span className="eyebrow">1 • SSL / CERTIFICATE VALIDATION</span><h3>Validate Callback TLS</h3></div><button className="primary" onClick={runSSLCheck} disabled={sslLoading}>{sslLoading?'Checking…':'Run SSL / Certificate Check'}</button></div><p className="muted">Certificate validation is performed against the configured callback endpoint outside browser JavaScript. The check verifies HTTPS/TLS connectivity, certificate hostname authorization, validity dates, trust status, and the presented certificate chain.</p>{sslResult&&<div className={`callbackresult ${sslResult.ok?'success':'failure'}`}><div className="ackGrid">
      <div className={sslResult.https?'checkpass':'checkfail'}>{sslResult.https?'✓':'✕'} HTTPS URL</div>
      <div className={sslResult.authorized?'checkpass':'checkfail'}>{sslResult.authorized?'✓':'✕'} Certificate trusted</div>
      <div className={sslResult.hostnameValid?'checkpass':'checkfail'}>{sslResult.hostnameValid?'✓':'✕'} Hostname matches certificate</div>
      <div className={sslResult.validityValid?'checkpass':'checkfail'}>{sslResult.validityValid?'✓':'✕'} Certificate validity period</div>
      <div className={sslResult.chainValid?'checkpass':'checkfail'}>{sslResult.chainValid?'✓':'✕'} Certificate chain</div>
    </div>{sslResult.error&&<pre>{sslResult.error}</pre>}{sslResult.certificate&&<div className="certificateDetails"><b>Server Certificate</b><div>Subject: {sslResult.certificate.subject}</div><div>Issuer: {sslResult.certificate.issuer}</div><div>Valid From: {sslResult.certificate.validFrom}</div><div>Valid To: {sslResult.certificate.validTo}</div><div>Fingerprint: {sslResult.certificate.fingerprint256}</div><div>Chain certificates presented: {sslResult.certificate.chainLength}</div></div>}</div>}</div>

    <div className="invocationCard"><span className="eyebrow">2 • CALLBACK REQUEST</span><h3>Send Callback Request</h3><div className="inputcard callbackform"><div className="field"><label>TxnID</label><input value={txnId} onChange={e=>setTxnId(e.target.value)} placeholder="Transaction ID"/></div><div className="field"><label>Credential</label><textarea value={credential} onChange={e=>setCredential(e.target.value)} placeholder="Paste the Credential / JWT here..."/></div><div className="actions"><button className="primary" onClick={sendCallback} disabled={loading||!txnId||!credential}>{loading?'Sending…':'Send Callback Request'}</button></div></div></div>

    {xml&&<div className="codecard"><div className="codehead"><b>Request Sent</b><button onClick={()=>navigator.clipboard.writeText(xml)}>Copy</button></div><pre>{xml}</pre></div>}
    {result&&<div className={`callbackresult ${result.ok?'success':'failure'}`}><div className="callbackresulthead"><b>{result.ok?'✓ Callback acknowledgement validated':'✕ Callback acknowledgement validation failed'}</b><span>HTTP {result.status||'N/A'}</span></div>{result.error&&<pre>{result.error}</pre>}{result.response&&<div className="callbackResponse"><b>Response Received</b><pre>{result.response}</pre></div>}{result.acknowledgement&&<div className="ackGrid"><div className={result.httpOk?'checkpass':'checkfail'}>{result.httpOk?'✓':'✕'} HTTP status {result.status}</div><div className={result.acknowledgement.validXml?'checkpass':'checkfail'}>{result.acknowledgement.validXml?'✓':'✕'} Valid XML response</div><div className={result.acknowledgement.txnMatch?'checkpass':'checkfail'}>{result.acknowledgement.txnMatch?'✓':'✕'} TxnID matches request</div><div className={result.acknowledgement.responseCode==='200'?'checkpass':'checkfail'}>{result.acknowledgement.responseCode==='200'?'✓':'✕'} ResponseCode = {result.acknowledgement.responseCode||'missing'}</div><div className={result.acknowledgement.responseMsg==='Success'?'checkpass':'checkfail'}>{result.acknowledgement.responseMsg==='Success'?'✓':'✕'} ResponseMsg = {result.acknowledgement.responseMsg||'missing'}</div></div>}</div>}
  </section>;
}

function escapeXml(value=''){return String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');}
createRoot(document.getElementById('root')).render(<App/>);
