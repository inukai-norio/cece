use crypto2::blockmode::*;

use super::{pkcs7, util};

pub fn encrypt(algorithm: &str, password: &str , salt: &str, info: &str, data: &str)-> Vec<u8> {
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

#[cfg(test)]
mod tests {
//    use super::*;

}
