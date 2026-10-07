import { generateKeyPair, SignJWT, jwtVerify, exportSPKI } from 'jose';
import { createHmac } from 'node:crypto';

const ISSUER = 'https://auth.miempresa.com';
const AUDIENCE = 'https://api.miempresa.com';
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

const { publicKey, privateKey } = await generateKeyPair('RS256');
const opts = { algorithms: ['RS256'], issuer: ISSUER, audience: AUDIENCE };

async function prueba(nombre, token) {
  try {
    await jwtVerify(token, publicKey, opts);
    console.log(`[FALLO DE SEGURIDAD] ${nombre}: aceptado`);
  } catch (e) {
    console.log(`[OK] ${nombre}: rechazado -> ${e.code ?? e.message}`);
  }
}

const claims = { sub: 'attacker', iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 600 };

await prueba('alg none', `${b64({alg:'none',typ:'JWT'})}.${b64(claims)}.`);

const pem = await exportSPKI(publicKey);
const data = `${b64({alg:'HS256',typ:'JWT'})}.${b64(claims)}`;
const sig = createHmac('sha256', pem).update(data).digest('base64url');
await prueba('confusión RS256/HS256', `${data}.${sig}`);

const expirado = await new SignJWT({}).setProtectedHeader({ alg: 'RS256' })
  .setSubject('user').setIssuer(ISSUER).setAudience(AUDIENCE)
  .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
  .setExpirationTime(Math.floor(Date.now() / 1000) - 60).sign(privateKey);
await prueba('token expirado', expirado);

const audMala = await new SignJWT({}).setProtectedHeader({ alg: 'RS256' })
  .setSubject('user').setIssuer(ISSUER).setAudience('https://otra-api.com')
  .setIssuedAt().setExpirationTime('5m').sign(privateKey);
await prueba('audiencia incorrecta', audMala);

const otra = await generateKeyPair('RS256');
const ajeno = await new SignJWT({}).setProtectedHeader({ alg: 'RS256' })
  .setSubject('user').setIssuer(ISSUER).setAudience(AUDIENCE)
  .setIssuedAt().setExpirationTime('5m').sign(otra.privateKey);
await prueba('llave de firma distinta', ajeno);