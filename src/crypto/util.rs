use crypto2::kdf::*;
use std::collections::VecDeque;
use regex::Regex;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_std};

pub fn check_algorithm(algorithm: &str)-> Option<[&str; 3]> {
    let re = Regex::new(r"^\s*(sha(?:224|256|384|512)|sm3)-((?:aes|aria|camellia)(?:128|192|256)|sm4)-(cbc|cfb(?:1|8|64|128)|ofb)\s*$").unwrap();
    if re.is_match(algorithm) {
        let caps = re.captures(algorithm).unwrap();
        Some([1, 2, 3].map(|i| caps.get(i).unwrap().as_str()))
    } else {
        None
    }
}

pub fn hkdf(algorithm: &str, password: &str , salt: &str, info: &str, key_len: usize, iv_len: usize)-> (Vec<u8>, Vec<u8>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto2::blockmode::*;

    mod algo {
        pub const H: [(&str, bool, &str); 8] = [
            ("sha224", true, "sha224"),
            ("sha256", true, "sha256"),
            ("sha384", true, "sha384"),
            ("sha512", true, "sha512"),
            ("sm3", true, "sm3"),

            ("md5", false, "md5"),

            ("ssha256", false, "ssha256"),
            (" sha512", true, "sha512"),
        ];
        pub const E: [(&str, bool, &str); 11] = [
            ("aes128", true, "aes128"),
            ("aes192", true, "aes192"),
            ("aes256", true, "aes256"),
            ("aria128", true, "aria128"),
            ("aria192", true, "aria192"),
            ("aria256", true, "aria256"),
            ("camellia128", true, "camellia128"),
            ("camellia192", true, "camellia192"),
            ("camellia256", true, "camellia256"),
            ("sm4", true, "sm4"),

            ("des", false, "des"),
        ];
        pub const M: [(&str, bool, &str); 9] = [
            ("cbc", true, "cbc"),
            ("cfb1", true, "cfb1"),
            ("cfb8", true, "cfb8"),
            ("cfb64", true, "cfb64"),
            ("cfb128", true, "cfb128"),
            ("ofb", true, "ofb"),

            ("ecb", false, "ecb"),

            ("cfb111", false, "cfb111"),
            ("cbc ", true, "cbc"),
        ];
    }


    #[test]
    fn test_check_algorithm() {
        for h in algo::H.into_iter() {
            for e in algo::E.into_iter() {
                for m in algo::M.into_iter() {
                    let a = &format!("{}-{}-{}", h.0, e.0, m.0);
                    let c = check_algorithm(a);
                    if h.1 & e.1 & m.1 {
                        let c_unwrap = c.unwrap();
                        assert_eq!(c_unwrap[0], h.2);
                        assert_eq!(c_unwrap[1], e.2);
                        assert_eq!(c_unwrap[2], m.2);
                    }
                    else {
                        assert!(c.is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn test_hkdf() {
        let h1 = vec!(
            ("sha224", "upOsTS7VSGipGSwEygZTZg==", "3I2NqGfVUN7JPfmQL38TvA=="),
            ("sha256", "63DwHe3pr6+kSe7hsShlBA==", "4fYjiLP33U+VZpew6Cj+GA=="),
            ("sha384", "RwzGU4fKShDHpoo7UUjI5Q==", "E9qmMQEABznExmWbhhGIhA=="),
            ("sha512", "nXPJjnkegOvltMtFaTqjLw==", "3US1+j7as+yC+dD01mkF4g=="),
            ("sm3", "YHH5F2KRkIiAdywJfmkuNg==", "DFNwevJ3PIReEj6tOz+01w=="),
            ("md5", "AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        for h in h1 {
            let (key, iv) = hkdf(h.0, "", "", "", Aes128Cbc::KEY_LEN, Aes128Cbc::IV_LEN);
            assert_eq!(base64_std.encode(key), h.1);
            assert_eq!(base64_std.encode(iv), h.2);
        }
    }
}
