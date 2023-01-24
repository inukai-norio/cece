use crypto2::blockmode::*;

use super::{pkcs7, util};

pub fn execute(algorithm: &str, password: &str , salt: &str, info: &str, data: Vec<u8>)-> String {
    let a = util::check_algorithm(algorithm).unwrap();

    macro_rules! make_key_and_iv {
        ($cipher:tt) => {
            {
                let (key, iv) = util::hkdf(a[0], password, salt, info, $cipher::KEY_LEN, $cipher::IV_LEN);
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
    macro_rules! cfb1_decrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = data.clone();
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).decrypt_slice(&iv, &mut ciphertext);
                String::from_utf8(pkcs7::decrypt(ciphertext.to_vec())).unwrap()
            }
        }
    }
    macro_rules! cfb8_decrypt {
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
    macro_rules! cfb128_decrypt {
        ($cipher:tt) => {
            {
                let mut ciphertext = data.clone();
                let (key, iv) = make_key_and_iv!($cipher);
                $cipher::new(&key).decrypt_slice(&iv, &mut ciphertext);
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
            "aes128" =>      cfb1_decrypt!(Aes128Cfb1),
            "aes192" =>      cfb1_decrypt!(Aes192Cfb1),
            "aes256" =>      cfb1_decrypt!(Aes256Cfb1),
            "aria128" =>     cfb1_decrypt!(Aria128Cfb1),
            "aria192" =>     cfb1_decrypt!(Aria192Cfb1),
            "aria256" =>     cfb1_decrypt!(Aria256Cfb1),
            "camellia128" => cfb1_decrypt!(Camellia128Cfb1),
            "camellia192" => cfb1_decrypt!(Camellia192Cfb1),
            "camellia256" => cfb1_decrypt!(Camellia256Cfb1),
            "sm4" =>         cfb1_decrypt!(Sm4Cfb1),
            _ => "".to_string()
        },
        "cfb8" => match a[1] {
            "aes128" =>      cfb8_decrypt!(Aes128Cfb8),
            "aes192" =>      cfb8_decrypt!(Aes192Cfb8),
            "aes256" =>      cfb8_decrypt!(Aes256Cfb8),
            "aria128" =>     cfb8_decrypt!(Aria128Cfb8),
            "aria192" =>     cfb8_decrypt!(Aria192Cfb8),
            "aria256" =>     cfb8_decrypt!(Aria256Cfb8),
            "camellia128" => cfb8_decrypt!(Camellia128Cfb8),
            "camellia192" => cfb8_decrypt!(Camellia192Cfb8),
            "camellia256" => cfb8_decrypt!(Camellia256Cfb8),
            "sm4" =>         cfb8_decrypt!(Sm4Cfb8),
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
            "aes128" =>      cfb128_decrypt!(Aes128Cfb128),
            "aes192" =>      cfb128_decrypt!(Aes192Cfb128),
            "aes256" =>      cfb128_decrypt!(Aes256Cfb128),
            "aria128" =>     cfb128_decrypt!(Aria128Cfb128),
            "aria192" =>     cfb128_decrypt!(Aria192Cfb128),
            "aria256" =>     cfb128_decrypt!(Aria256Cfb128),
            "camellia128" => cfb128_decrypt!(Camellia128Cfb128),
            "camellia192" => cfb128_decrypt!(Camellia192Cfb128),
            "camellia256" => cfb128_decrypt!(Camellia256Cfb128),
            "sm4" =>         cfb128_decrypt!(Sm4Cfb128),
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

#[cfg(test)]
mod tests {
//    use super::*;

}
