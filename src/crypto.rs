extern crate crypto2;

use crypto2::blockmode::*;
use crypto2::kdf::*;
use std::collections::VecDeque;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_std};

mod pkcs7 {
    pub fn encrypt(data: Vec<u8>, block_len: usize)-> Vec<u8> {
        let len = data.len();
        let d: u8 = std::convert::TryFrom::try_from(block_len - (len % block_len)).unwrap();
        let mut plaintext = data;
        for a in vec![d; d.into()] {
            plaintext.push(a);
        }
        plaintext
    }
    
    pub fn decrypt(data: Vec<u8>)-> Vec<u8> {
        let mut plaintext = data;
        let l = plaintext.pop();
        for _i in 2..=l.unwrap() {
            if plaintext.pop() != l {
    //            Err('???');
            }
        }
        plaintext
    }    
}

fn check_algorithm(algorithm: &str)-> Option<[&str; 3]> {
    let re = Regex::new(r"^\s*(sha(?:224|256|384|512)|sm3)-((?:aes|aria|camellia)(?:128|192|256)|sm4)-(cbc|cfb(?:1|8|64|128)|ofb)\s*$").unwrap();
    if re.is_match(algorithm) {
        let caps = re.captures(algorithm).unwrap();
        Some([1, 2, 3].map(|i| caps.get(i).unwrap().as_str()))
    } else {
        None
    }
}

fn hkdf(algorithm: &str, password: &str , salt: &str, info: &str, key_len: usize, iv_len: usize)-> (Vec<u8>, Vec<u8>) {
    let mut duf = [0u8; 128];
    macro_rules! hkdf_oneshot {
        ($c:tt) => {
            $c::oneshot(&base64_std.decode(salt).unwrap(), password.as_bytes(), info.as_bytes(), &mut duf)
        }
    }
    match algorithm {
        "sha224" => hkdf_oneshot!(HkdfSha224),
        "sha256" => hkdf_oneshot!(HkdfSha256),
        "sha384" => hkdf_oneshot!(HkdfSha384),
        "sha512" => hkdf_oneshot!(HkdfSha512),
        "sm3"    => hkdf_oneshot!(HkdfSm3),
        _ => ()
    }
    let mut okm: VecDeque<u8> = duf.iter().copied().collect();
    
    let mut key: Vec<u8> = Vec::new();
    for _i in 0..key_len {
        key.push(okm.pop_front().unwrap());
    }
    let mut iv: Vec<u8> = Vec::new();
    for _i in 0..iv_len {
        iv.push(okm.pop_front().unwrap());
    }
    (key, iv)
}

pub fn encrypt(algorithm: &str, password: &str , salt: &str, info: &str, data: &str)-> Vec<u8> {
    let a = check_algorithm(algorithm).unwrap();

    macro_rules! make_key_and_iv {
        ($cipher:tt) => {
            {
                let (key, iv) = hkdf(a[0], password, salt, info, $cipher::KEY_LEN, $cipher::IV_LEN);
                let iv_a = [0u8; $cipher::IV_LEN].map(|_| *iv.iter().next().unwrap());
                (key, iv_a)
            }
        }
    }
    macro_rules! cbc_encrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = pkcs7::encrypt(data.as_bytes().to_vec(), $cipher::BLOCK_LEN);
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).encrypt(&iv, &mut ciphertext);
                ciphertext.to_vec()
            }
        }
    }
    macro_rules! cfb_encrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = pkcs7::encrypt(data.as_bytes().to_vec(), $cipher::BLOCK_LEN);
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).encrypt_slice(&iv, &mut ciphertext);
                ciphertext.to_vec()
            }
        }
    }
    macro_rules! cfb64_encrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = pkcs7::encrypt(data.as_bytes().to_vec(), $cipher::BLOCK_LEN);
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).encrypt(&iv, &mut ciphertext);
                ciphertext.to_vec()
            }
        }
    }
    macro_rules! ofb_encrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = pkcs7::encrypt(data.as_bytes().to_vec(), $cipher::BLOCK_LEN);
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).encrypt_slice(&iv, &mut ciphertext);
                ciphertext.to_vec()
            }
        }
    }
    match a[2] {
        "cbc" => match a[1] {
            "aes128" =>      cbc_encrypt!(Aes128Cbc),
            "aes192" =>      cbc_encrypt!(Aes192Cbc),
            "aes256" =>      cbc_encrypt!(Aes256Cbc),
            "aria128" =>     cbc_encrypt!(Aria128Cbc),
            "aria192" =>     cbc_encrypt!(Aria192Cbc),
            "aria256" =>     cbc_encrypt!(Aria256Cbc),
            "camellia128" => cbc_encrypt!(Camellia128Cbc),
            "camellia192" => cbc_encrypt!(Camellia192Cbc),
            "camellia256" => cbc_encrypt!(Camellia256Cbc),
            "sm4" =>         cbc_encrypt!(Sm4Cbc),
            _ => vec![0u8]
        },
        "cfb1" => match a[1] {
            "aes128" =>      cfb_encrypt!(Aes128Cfb1),
            "aes192" =>      cfb_encrypt!(Aes192Cfb1),
            "aes256" =>      cfb_encrypt!(Aes256Cfb1),
            "aria128" =>     cfb_encrypt!(Aria128Cfb1),
            "aria192" =>     cfb_encrypt!(Aria192Cfb1),
            "aria256" =>     cfb_encrypt!(Aria256Cfb1),
            "camellia128" => cfb_encrypt!(Camellia128Cfb1),
            "camellia192" => cfb_encrypt!(Camellia192Cfb1),
            "camellia256" => cfb_encrypt!(Camellia256Cfb1),
            "sm4" =>         cfb_encrypt!(Sm4Cfb1),
            _ => vec![0u8]
        },
        "cfb8" => match a[1] {
            "aes128" =>      cfb_encrypt!(Aes128Cfb8),
            "aes192" =>      cfb_encrypt!(Aes192Cfb8),
            "aes256" =>      cfb_encrypt!(Aes256Cfb8),
            "aria128" =>     cfb_encrypt!(Aria128Cfb8),
            "aria192" =>     cfb_encrypt!(Aria192Cfb8),
            "aria256" =>     cfb_encrypt!(Aria256Cfb8),
            "camellia128" => cfb_encrypt!(Camellia128Cfb8),
            "camellia192" => cfb_encrypt!(Camellia192Cfb8),
            "camellia256" => cfb_encrypt!(Camellia256Cfb8),
            "sm4" =>         cfb_encrypt!(Sm4Cfb8),
            _ => vec![0u8]
        },
        "cfb64" => match a[1] {
            "aes128" =>      cfb64_encrypt!(Aes128Cfb64),
            "aes192" =>      cfb64_encrypt!(Aes192Cfb64),
            "aes256" =>      cfb64_encrypt!(Aes256Cfb64),
            "aria128" =>     cfb64_encrypt!(Aria128Cfb64),
            "aria192" =>     cfb64_encrypt!(Aria192Cfb64),
            "aria256" =>     cfb64_encrypt!(Aria256Cfb64),
            "camellia128" => cfb64_encrypt!(Camellia128Cfb64),
            "camellia192" => cfb64_encrypt!(Camellia192Cfb64),
            "camellia256" => cfb64_encrypt!(Camellia256Cfb64),
            "sm4" =>         cfb64_encrypt!(Sm4Cfb64),
            _ => vec![0u8]
        },
        "cfb128" => match a[1] {
            "aes128" =>      cfb_encrypt!(Aes128Cfb128),
            "aes192" =>      cfb_encrypt!(Aes192Cfb128),
            "aes256" =>      cfb_encrypt!(Aes256Cfb128),
            "aria128" =>     cfb_encrypt!(Aria128Cfb128),
            "aria192" =>     cfb_encrypt!(Aria192Cfb128),
            "aria256" =>     cfb_encrypt!(Aria256Cfb128),
            "camellia128" => cfb_encrypt!(Camellia128Cfb128),
            "camellia192" => cfb_encrypt!(Camellia192Cfb128),
            "camellia256" => cfb_encrypt!(Camellia256Cfb128),
            "sm4" =>         cfb_encrypt!(Sm4Cfb128),
            _ => vec![0u8]
        },
        "ofb" => match a[1] {
            "aes128" =>      ofb_encrypt!(Aes128Ofb),
            "aes192" =>      ofb_encrypt!(Aes192Ofb),
            "aes256" =>      ofb_encrypt!(Aes256Ofb),
            "aria128" =>     ofb_encrypt!(Aria128Ofb),
            "aria192" =>     ofb_encrypt!(Aria192Ofb),
            "aria256" =>     ofb_encrypt!(Aria256Ofb),
            "camellia128" => ofb_encrypt!(Camellia128Ofb),
            "camellia192" => ofb_encrypt!(Camellia192Ofb),
            "camellia256" => ofb_encrypt!(Camellia256Ofb),
            "sm4" =>         ofb_encrypt!(Sm4Ofb),
            _ => vec![0u8]
        }
        _ => vec![0u8]
    }
}

pub fn decrypt(algorithm: &str, password: &str , salt: &str, info: &str, data: Vec<u8>)-> String {
    let a = check_algorithm(algorithm).unwrap();

    macro_rules! make_key_and_iv {
        ($cipher:tt) => {
            {
                let (key, iv) = hkdf(a[0], password, salt, info, $cipher::KEY_LEN, $cipher::IV_LEN);
                let iv_a = [0u8; $cipher::IV_LEN].map(|_| *iv.iter().next().unwrap());
                (key, iv_a)
            }
        }
    }
    macro_rules! cbc_decrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = data.clone();
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).decrypt(&iv, &mut ciphertext);
                String::from_utf8(pkcs7::decrypt(ciphertext.to_vec())).unwrap()
            }
        }
    }
    macro_rules! cfb_decrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = data.clone();
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).decrypt_slice(&iv, &mut ciphertext);
                String::from_utf8(pkcs7::decrypt(ciphertext.to_vec())).unwrap()
            }
        }
    }
    macro_rules! cfb64_decrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = data.clone();
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).decrypt(&iv, &mut ciphertext);
                String::from_utf8(pkcs7::decrypt(ciphertext.to_vec())).unwrap()
            }
        }
    }
    macro_rules! ofb_decrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = data.clone();
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).decrypt_slice(&iv, &mut ciphertext);
                String::from_utf8(pkcs7::decrypt(ciphertext.to_vec())).unwrap()
            }
        }
    }
    match a[2] {
        "cbc" => match a[1] {
            "aes128" =>      cbc_decrypt!(Aes128Cbc),
            "aes192" =>      cbc_decrypt!(Aes192Cbc),
            "aes256" =>      cbc_decrypt!(Aes256Cbc),
            "aria128" =>     cbc_decrypt!(Aria128Cbc),
            "aria192" =>     cbc_decrypt!(Aria192Cbc),
            "aria256" =>     cbc_decrypt!(Aria256Cbc),
            "camellia128" => cbc_decrypt!(Camellia128Cbc),
            "camellia192" => cbc_decrypt!(Camellia192Cbc),
            "camellia256" => cbc_decrypt!(Camellia256Cbc),
            "sm4" =>         cbc_decrypt!(Sm4Cbc),
            _ => "".to_string()
        },
        "cfb1" => match a[1] {
            "aes128" =>      cfb_decrypt!(Aes128Cfb1),
            "aes192" =>      cfb_decrypt!(Aes192Cfb1),
            "aes256" =>      cfb_decrypt!(Aes256Cfb1),
            "aria128" =>     cfb_decrypt!(Aria128Cfb1),
            "aria192" =>     cfb_decrypt!(Aria192Cfb1),
            "aria256" =>     cfb_decrypt!(Aria256Cfb1),
            "camellia128" => cfb_decrypt!(Camellia128Cfb1),
            "camellia192" => cfb_decrypt!(Camellia192Cfb1),
            "camellia256" => cfb_decrypt!(Camellia256Cfb1),
            "sm4" =>         cfb_decrypt!(Sm4Cfb1),
            _ => "".to_string()
        },
        "cfb8" => match a[1] {
            "aes128" =>      cfb_decrypt!(Aes128Cfb8),
            "aes192" =>      cfb_decrypt!(Aes192Cfb8),
            "aes256" =>      cfb_decrypt!(Aes256Cfb8),
            "aria128" =>     cfb_decrypt!(Aria128Cfb8),
            "aria192" =>     cfb_decrypt!(Aria192Cfb8),
            "aria256" =>     cfb_decrypt!(Aria256Cfb8),
            "camellia128" => cfb_decrypt!(Camellia128Cfb8),
            "camellia192" => cfb_decrypt!(Camellia192Cfb8),
            "camellia256" => cfb_decrypt!(Camellia256Cfb8),
            "sm4" =>         cfb_decrypt!(Sm4Cfb8),
            _ => "".to_string()
        },
        "cfb64" => match a[1] {
            "aes128" =>      cfb64_decrypt!(Aes128Cfb64),
            "aes192" =>      cfb64_decrypt!(Aes192Cfb64),
            "aes256" =>      cfb64_decrypt!(Aes256Cfb64),
            "aria128" =>     cfb64_decrypt!(Aria128Cfb64),
            "aria192" =>     cfb64_decrypt!(Aria192Cfb64),
            "aria256" =>     cfb64_decrypt!(Aria256Cfb64),
            "camellia128" => cfb64_decrypt!(Camellia128Cfb64),
            "camellia192" => cfb64_decrypt!(Camellia192Cfb64),
            "camellia256" => cfb64_decrypt!(Camellia256Cfb64),
            "sm4" =>         cfb64_decrypt!(Sm4Cfb64),
            _ => "".to_string()
        },
        "cfb128" => match a[1] {
            "aes128" =>      cfb_decrypt!(Aes128Cfb128),
            "aes192" =>      cfb_decrypt!(Aes192Cfb128),
            "aes256" =>      cfb_decrypt!(Aes256Cfb128),
            "aria128" =>     cfb_decrypt!(Aria128Cfb128),
            "aria192" =>     cfb_decrypt!(Aria192Cfb128),
            "aria256" =>     cfb_decrypt!(Aria256Cfb128),
            "camellia128" => cfb_decrypt!(Camellia128Cfb128),
            "camellia192" => cfb_decrypt!(Camellia192Cfb128),
            "camellia256" => cfb_decrypt!(Camellia256Cfb128),
            "sm4" =>         cfb_decrypt!(Sm4Cfb128),
            _ => "".to_string()
        },
        "ofb" => match a[1] {
            "aes128" =>      ofb_decrypt!(Aes128Ofb),
            "aes192" =>      ofb_decrypt!(Aes192Ofb),
            "aes256" =>      ofb_decrypt!(Aes256Ofb),
            "aria128" =>     ofb_decrypt!(Aria128Ofb),
            "aria192" =>     ofb_decrypt!(Aria192Ofb),
            "aria256" =>     ofb_decrypt!(Aria256Ofb),
            "camellia128" => ofb_decrypt!(Camellia128Ofb),
            "camellia192" => ofb_decrypt!(Camellia192Ofb),
            "camellia256" => ofb_decrypt!(Camellia256Ofb),
            "sm4" =>         ofb_decrypt!(Sm4Ofb),
            _ => "".to_string()
        }
        _ => "".to_string()
    }
}
