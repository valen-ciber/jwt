import { generateKeyPair, EncryptJWT, jwtDecrypt } from 'jose';

const ISSUER = 'https://auth.miempresa.com';
const AUDIENCE = 'https://api.miempresa.com';

const { publicKey, privateKey } = await generateKeyPair('RSA-OAEP-256');

const jwe = await new EncryptJWT({ documento: '1234567890', email: 'ana@example.com' })
  .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
  .setSubject('user-123')
  .setIssuer(ISSUER)
  .setAudience(AUDIENCE)
  .setIssuedAt()
  .setExpirationTime('10m')
  .encrypt(publicKey);

console.log('JWE (5 partes):\n', jwe, '\n');
console.log('Partes:', jwe.split('.').length);

console.log('Header (único legible):', JSON.parse(Buffer.from(jwe.split('.')[0], 'base64url').toString()));

const { payload } = await jwtDecrypt(jwe, privateKey, {
  issuer: ISSUER,
  audience: AUDIENCE,
  keyManagementAlgorithms: ['RSA-OAEP-256'],
  contentEncryptionAlgorithms: ['A256GCM'],
});
console.log('Descifrado:', payload);