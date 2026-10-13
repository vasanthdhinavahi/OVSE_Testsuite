import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import https from 'node:https';
import tls from 'node:tls';
import {OVSE_CONFIG} from './src/config.js';

const callbackUrl = new URL(OVSE_CONFIG.callbackUrl);

function certificateDetails(cert) {
  const chain = [];
  const seen = new Set();
  let current = cert;

  while (current && typeof current === 'object') {
    const id = current.fingerprint256 || `${current.subject || ''}|${current.serialNumber || ''}`;
    if (seen.has(id)) break;
    seen.add(id);
    chain.push(current);
    if (!current.issuerCertificate || current.issuerCertificate === current) break;
    current = current.issuerCertificate;
  }

  return {
    subject: cert.subject?.CN || cert.subject || '',
    issuer: cert.issuer?.CN || cert.issuer || '',
    validFrom: cert.valid_from || '',
    validTo: cert.valid_to || '',
    fingerprint256: cert.fingerprint256 || '',
    chainLength: chain.length
  };
}

function sslCheckMiddleware() {
  return {
    name: 'ovse-ssl-certificate-check',
    configureServer(server) {
      server.middlewares.use('/api/callback-ssl-check', (req, res) => {
        if (req.method !== 'GET') {
          res.statusCode = 405;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ok:false,error:'Method not allowed'}));
          return;
        }

        if (callbackUrl.protocol !== 'https:') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            ok:false,
            https:false,
            authorized:false,
            hostnameValid:false,
            validityValid:false,
            chainValid:false,
            error:'Callback URL must use HTTPS for SSL / certificate validation.'
          }));
          return;
        }

        const hostname = callbackUrl.hostname;
        const ipHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');
        const options = {
          hostname,
          port: callbackUrl.port ? Number(callbackUrl.port) : 443,
          path: callbackUrl.pathname + callbackUrl.search,
          method: 'HEAD',
          rejectUnauthorized: false,
          timeout: 10000
        };
        if (!ipHost) options.servername = hostname;

        let request;
        try {
          request = https.request(options, response => {
          const socket = response.socket;
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized === true;
          const authorizationError = socket.authorizationError || '';
          const now = new Date();
          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const validityValid = !!validFrom && !!validTo && now >= validFrom && now <= validTo;
          const hostnameValid = authorized && !authorizationError;
          const chain = certificateDetails(cert);
          const chainValid = chain.chainLength >= 2;

          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            ok: authorized && hostnameValid && validityValid && chainValid,
            https:true,
            authorized,
            hostnameValid,
            validityValid,
            chainValid,
            statusCode: response.statusCode,
            error: authorizationError || null,
            certificate: chain
          }));
          response.resume();
        });

        } catch (error) {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            ok:false,
            https:true,
            authorized:false,
            hostnameValid:false,
            validityValid:false,
            chainValid:false,
            error:error.message
          }));
          return;
        }

        request.on('timeout', () => request.destroy(new Error('TLS connection timed out.')));
        request.on('error', error => {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            ok:false,
            https:true,
            authorized:false,
            hostnameValid:false,
            validityValid:false,
            chainValid:false,
            error:error.message
          }));
        });
        request.end();
      });
    }
  };
}

export default defineConfig({
  plugins:[react(), sslCheckMiddleware()],
  server:{
    proxy:{
      '/api/callback-test':{
        target: callbackUrl.origin,
        changeOrigin:true,
        secure:true,
        rewrite:()=>callbackUrl.pathname + callbackUrl.search
      }
    }
  }
});
