


use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use regex::Regex;

mod crypto;

fn main() {

    let mut csp_rng = ChaCha20Rng::from_entropy();
    let mut data = [0u8; 32];
    csp_rng.fill_bytes(&mut data);

    println!("Some numbers: {:?}", data);

    let salt = &base64::encode(&data[..]);
    let passwd = "1234567890";
    let algo = "sha256-aria192-cbc";
    let info = "";

    let text = "123456789abcdefr";
    println!("a: {:?}", text);
    let b = crypto::encrypt(algo, passwd, salt, info, text);
    let c = base64::encode(&b[..]);
    
    let d = format!("{}:{}:{}:{}", algo, salt, info, c);
    println!("d: {:?}", d);

    let caps = Regex::new(r"([^:]+):([0-9A-Za-z+/=]+):([^:]*):([0-9A-Za-z+/=]+)").unwrap().captures(&d).unwrap();

    let y = &base64::decode(caps.get(4).unwrap().as_str()).unwrap();
    let z = crypto::decrypt(caps.get(1).unwrap().as_str(), passwd, caps.get(2).unwrap().as_str(), caps.get(3).unwrap().as_str(), y.to_vec());
    println!("z: {:?}", z);
}
