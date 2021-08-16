use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use regex::Regex;

mod crypto;

fn main() {
    let mut csp_rng = ChaCha20Rng::from_entropy();

    let passwd = "1234567890";
    let algo = "sha256-aria192-cbc";
    let info = "";

    let mut file = File::create("d").unwrap();
    for result in BufReader::new(File::open("a").unwrap()).lines() {
        let l = result.unwrap();

        let mut data = [0u8; 32];
        csp_rng.fill_bytes(&mut data);

        let salt = &base64::encode(&data[..]);
        if Regex::new(r"^(#.*|\s*)$").unwrap().is_match(&l) {
            let _ = writeln!(file, "{}", l);
            continue;
        }
        let r = Regex::new(r"^([^=]+)=(.*)$").unwrap().captures(&l).unwrap();
        
        let b = crypto::encrypt(algo, passwd, salt, info, r.get(2).unwrap().as_str());
        let c = base64::encode(&b[..]);

        let d = format!("{}={}:{}:{}:{}", r.get(1).unwrap().as_str(), algo, salt, info, c);
        let _ = writeln!(file, "{}", d);
    }
    file.flush().unwrap();

    let mut file2 = File::create("e").unwrap();
    for result in BufReader::new(File::open("d").unwrap()).lines() {
        let l = result.unwrap();
        if Regex::new(r"^(#.*|\s*)$").unwrap().is_match(&l) {
            let _ = writeln!(file2, "{}", l);
            continue;
        }
        let caps = Regex::new(r"^([^=]+)=([^:]+):([0-9A-Za-z+/=]+):([^:]*):([0-9A-Za-z+/=]+)$").unwrap().captures(&l).unwrap();
        let y = &base64::decode(caps.get(5).unwrap().as_str()).unwrap();
        let z = crypto::decrypt(caps.get(2).unwrap().as_str(), passwd, caps.get(3).unwrap().as_str(), caps.get(4).unwrap().as_str(), y.to_vec());
        let zz = format!("{}={}", caps.get(1).unwrap().as_str(), z);
        let _ = writeln!(file2, "{}", zz);
    }
    file2.flush().unwrap();
}
