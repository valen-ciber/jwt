import { generateKeyPair, SignJWT, jwtVerify, CompactEncrypt, compactDecrypt } from 'jose';

const ISSUER = 'https://auth.miempresa.com';
const AUDIENCE = 'https://api.miempresa.com';

const signing = await generateKeyPair('ES256');
const encryption = await generateKeyPair('RSA-OAEP-256');

const jws = await new SignJWT({ documento: '1234567890' })
  .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
  .setSubject('user-123')
  .setIssuer(ISSUER)
  .setAudience(AUDIENCE)
  .setIssuedAt()
  .setExpirationTime('5m')
  .sign(signing.privateKey);

const jwe = await new CompactEncrypt(new TextEncoder().encode(jws))
  .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
  .encrypt(encryption.publicKey);

console.log('JWT anidado (JWE que contiene un JWS):\n', jwe, '\n');

const { plaintext, protectedHeader } = await compactDecrypt(jwe, encryption.privateKey, {
  keyManagementAlgorithms: ['RSA-OAEP-256'],
  contentEncryptionAlgorithms: ['A256GCM'],
});
if (protectedHeader.cty !== 'JWT') throw new Error('cty inesperado');

const { payload } = await jwtVerify(new TextDecoder().decode(plaintext), signing.publicKey, {
  algorithms: ['ES256'],
  issuer: ISSUER,
  audience: AUDIENCE,
});
console.log('Verificado tras descifrar:', payload);