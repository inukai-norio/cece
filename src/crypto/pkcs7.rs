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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as base64_std};
    #[test]
    fn test_encrypt() {
        let data = "";
        let a = encrypt(data.as_bytes().to_vec(), 16);
        assert_eq!(base64_std.encode(a), "EBAQEBAQEBAQEBAQEBAQEA==");
    }

    #[test]
    fn test_decrypt() {
        let a = decrypt(base64_std.decode("EBAQEBAQEBAQEBAQEBAQEA==").unwrap());
        assert_eq!(base64_std.encode(a), "");
    }
}
