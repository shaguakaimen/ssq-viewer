const FORMAT = 'ssq-encrypted-v1';
const ITERATIONS = 600_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(bytes) {
  let result = '';
  for (const value of new Uint8Array(bytes)) result += String.fromCharCode(value);
  return btoa(result);
}
function fromBase64(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error('Invalid encrypted file');
  return Uint8Array.from(atob(text), char => char.charCodeAt(0));
}
async function keyFor(password, salt, usage) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material,
    { name: 'AES-GCM', length: 256 }, false, [usage]);
}
export async function encryptPayload(value, password) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 256 || /[\r\n]/.test(password)) {
    throw new Error('VIEWER_PASSWORD must contain 16 to 256 characters');
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await keyFor(password, salt, 'encrypt');
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(FORMAT), tagLength: 128 },
    key, encoder.encode(JSON.stringify(value)));
  return { format: FORMAT, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, cipher: 'AES-256-GCM',
    salt: toBase64(salt), iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}
export async function decryptPayload(envelope, password) {
  if (envelope?.format !== FORMAT || envelope.kdf !== 'PBKDF2-SHA256' || envelope.iterations !== ITERATIONS || envelope.cipher !== 'AES-256-GCM') {
    throw new Error('Unsupported encrypted file');
  }
  const salt = fromBase64(envelope.salt), iv = fromBase64(envelope.iv), ciphertext = fromBase64(envelope.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17 || ciphertext.length > 5_000_000) throw new Error('Invalid encrypted file');
  const key = await keyFor(password, salt, 'decrypt');
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(FORMAT), tagLength: 128 }, key, ciphertext);
  const value = JSON.parse(decoder.decode(raw));
  if (typeof value.html !== 'string' || !value.data?.latest) throw new Error('Invalid dashboard content');
  return value;
}
