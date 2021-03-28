import * as yaml from 'js-yaml';
import fs from 'fs'
import * as crypto from 'crypto';
import { encrypt, decrypt, encryptBase64, decryptBase64 } from './crypto';

const ALGO = 'camellia-256-cbc'

type Data = {
  encrypt: string;
  algorithm: string;
  salt: string;
}

type EncryptData = {[feald: string]: Data}

const encryptyYaml = (yamlString: string, password: string): string => {
  const b: EncryptData = {};
  yamlString.split(/\n|\r|\r\n/).map((line) => {
    const v = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/)
    if (v != null) {
      const salt = crypto.randomBytes(32)
      return {
        key: v[1],
        value: {
          encrypt: encrypt(ALGO, password, salt, v[2] || ''),
          algorithm: ALGO,
          salt: encryptBase64(salt),
        }
      }
    }
    return null;
  }).forEach((v) => {
    if(v !== null) {
      b[v.key] = v.value;
    }
  })
  return yaml.dump(b);
}

const decryptData = (password: string) => (v: [string, Data]) => {
  if (v[1] === undefined) {
    throw new Error();
  }
  return {
    key: v[0],
    value: decrypt(v[1].algorithm ,password, decryptBase64(v[1].salt), v[1].encrypt),
  }
}

const decryptyYaml = (yamlString: string, password: string): string => Object.entries(<EncryptData>yaml.load(yamlString)).map(decryptData(password)).map((v) => `${v.key}=${v.value}`).join('\n');

const e = encryptyYaml(fs.readFileSync('a', {encoding: 'utf8'}),'abc');
fs.writeFileSync('b', e);
const d = decryptyYaml(fs.readFileSync('b', {encoding: 'utf8'}), 'abc');
console.log(d);
