import { generateKeyPair, SignJWT, jwtVerify, exportJWK } from 'jose';

const ISSUER = 'https://auth.miempresa.com';
const AUDIENCE = 'https://api.miempresa.com';

const { publicKey, privateKey } = await generateKeyPair('ES256');

const jwt = await new SignJWT({ role: 'admin' })
  .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: 'key-2026-01' })
  .setSubject('user-123')
  .setIssuer(ISSUER)
  .setAudience(AUDIENCE)
  .setIssuedAt()
  .setExpirationTime('10m')
  .setJti(crypto.randomUUID())
  .sign(privateKey);

console.log('JWT firmado:\n', jwt, '\n');

const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
  algorithms: ['ES256'],
  issuer: ISSUER,
  audience: AUDIENCE,
});
console.log('Verificado. Header:', protectedHeader);
console.log('Payload:', payload);

const legible = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
console.log('\nPayload leído SIN verificar (por eso no es confidencial):', legible);
console.log('\nJWK público:', { ...(await exportJWK(publicKey)), kid: 'key-2026-01', alg: 'ES256', use: 'sig' });