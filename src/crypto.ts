import * as crypto from 'crypto';

const getKeySize = (algorithm: string): { keySize: number, ivSize: number} => {
  const a = algorithm.split('-');
  const keySize = (() => {
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
    if(a[0] === 'seed') {
      return 16;
    }
    return 8;
  })();
  return {keySize, ivSize}
}

const pbkdf2 = (hash: string, password: crypto.BinaryLike, salt: crypto.BinaryLike, iterations: number, algorithm: string): { key: Buffer, iv: Buffer} => {
  const {keySize, ivSize} = getKeySize(algorithm);
  const ret = crypto.pbkdf2Sync(password, salt, iterations, keySize + ivSize, hash);
  const key = ret.slice(0, keySize);
  const iv = ret.slice(keySize, keySize + ivSize);
  return {key, iv}
}

export const encrypt = (algorithm: string, hash: string, password: crypto.BinaryLike, salt: crypto.BinaryLike, iterations: number, data: string): string => {
  const {key, iv} = pbkdf2(hash, password, salt, iterations, algorithm)
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedData = cipher.update(Buffer.from(data, 'utf-8'));
  encryptedData = Buffer.concat([encryptedData, cipher.final()])
  return encryptedData.toString('base64')
}

export const decrypt = (algorithm: string, hash: string, password: crypto.BinaryLike, salt: crypto.BinaryLike, iterations: number, data: string): string => {
  const {key, iv} = pbkdf2(hash, password, salt, iterations, algorithm)
  const decipher = crypto.createDecipheriv(algorithm, key, iv)
  let decryptedData = decipher.update(Buffer.from(data, 'base64'))
  decryptedData =  Buffer.concat([decryptedData, decipher.final()])
  return decryptedData.toString('utf-8')
}
