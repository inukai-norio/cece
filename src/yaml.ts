import * as yaml from 'js-yaml';
import fs from 'fs'
import * as crypto from 'crypto';
import { encrypt, decrypt, encryptBase64, decryptBase64 } from './crypto';

const ALGO = 'camellia-256-cbc'

type EncryptData = {[feald: string]: {
  encrypt: string;
  algorithm: string;
  salt: string;
}}

type DecryptData = {[feald: string]: string}

class CryptYaml {
  private file: string;

  private yamlString: string;

  constructor(file: string) {
    this.file = file;
    this.yamlString = fs.readFileSync(this.file, {encoding: 'utf8'});
  }

  public encryptyYaml(password: string): string  {
    const b: EncryptData = {};
    Object.entries(<DecryptData>yaml.load(this.yamlString)).map((v) => { 
      if (v[1] === undefined) {
        throw new Error();
      }
      const salt = crypto.randomBytes(32)
      return {
        key: v[0],
        value: {
          encrypt: encrypt(ALGO, password, salt, v[1]),
          algorithm: ALGO,
          salt: encryptBase64(salt),
        }
      }
    }).forEach((v) => {
      b[v.key] = v.value;
    })
    
    return yaml.dump(b);
  }
  
  public decryptyYaml(password: string): string {
    const a: DecryptData = {};
    Object.entries(<EncryptData>yaml.load(this.yamlString)).map((v) => {
      if (v[1] === undefined) {
        throw new Error();
      }
      return {
        key: v[0],
        value: decrypt(v[1].algorithm ,password, decryptBase64(v[1].salt), v[1].encrypt),
      }
    }).forEach((v) => {
      a[v.key] = v.value;
    });
    
    return yaml.dump(a);
  }
}

const a = new CryptYaml('a');
const e = a.encryptyYaml('abc');
fs.writeFileSync('b', e);
const b = new CryptYaml('b');
const d = b.decryptyYaml('abc');
console.log(d);
