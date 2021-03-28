import * as crypto from 'crypto';

const N = 76;

export const encryptBase64 = (data: Buffer): string => {
  const base64 = data.toString('base64')
  const base64Array: string[] = [];
  for (let i = 0, j = 0; i < base64.length; i += N, j += 1) {
    base64Array[j] = base64.slice(i, i + N);
  }
  return base64Array.join('\n');
}

export const decryptBase64 = (data: string): Buffer => Buffer.from(data.split('\n').join(), 'base64')

const getKeySize = (algorithm: string): { keySize: number, ivSize: number} => {
  const a = algorithm.split('-');
  const keySize = (() => {
    if(a[0] === 'sm4') {
      return 16;
    }
    if(a[1] === '256') {
      return 32;
    }
    if(a[1] === '196') {
      return 24;
    }
    if(a[1] === '128') {
      return 16;
    }
    return 8;
  })();
  const ivSize = (() => {
    if(a[0] === 'aes') {
      return 16;
    }
    if(a[0] === 'camellia') {
      return 16;
    }
    if(a[0] === 'aria') {
      return 16;
    }
    if(a[0] === 'sm4') {
      return 16;
    }
    return 8;
  })();
  return {keySize, ivSize}
}

const scrypt = (password: crypto.BinaryLike, salt: crypto.BinaryLike, algorithm: string): { key: Buffer, iv: Buffer} => {
  const {keySize, ivSize} = getKeySize(algorithm);
  const ret = crypto.scryptSync(password, salt, keySize + ivSize)
  const key = ret.slice(0, keySize);
  const iv = ret.slice(keySize, keySize + ivSize);
  return {key, iv}
}

export const encrypt = (algorithm: string, password: crypto.BinaryLike, salt: crypto.BinaryLike, data: string): string => {
  const {key, iv} = scrypt(password, salt, algorithm)
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedData = cipher.update(Buffer.from(data, 'utf-8'));
  encryptedData = Buffer.concat([encryptedData, cipher.final()])
  return encryptBase64(encryptedData);
}

export const decrypt = (algorithm: string, password: crypto.BinaryLike, salt: crypto.BinaryLike, data: string): string => {
  const {key, iv} = scrypt(password, salt, algorithm)
  const decipher = crypto.createDecipheriv(algorithm, key, iv)
  let decryptedData = decipher.update(decryptBase64(data))
  decryptedData =  Buffer.concat([decryptedData, decipher.final()])
  return decryptedData.toString('utf-8')
}
