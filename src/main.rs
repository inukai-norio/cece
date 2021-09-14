extern crate getopts;

use getopts::Options;
use std::env;
use std::process;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use regex::Regex;

mod crypto;

fn is_comment(l: &str) -> bool {
    Regex::new(r"^(#.*|\s*)$").unwrap().is_match(l)
}

fn encode(infile: &str, outfile: &str, passwd: &str, algo: &str, info: &str) {
    let mut csp_rng = ChaCha20Rng::from_entropy();
    let mut file = File::create(outfile).unwrap();
    for result in BufReader::new(File::open(infile).unwrap()).lines() {
        let l = result.unwrap();

        let mut data = [0u8; 32];
        csp_rng.fill_bytes(&mut data);

        let salt = &base64::encode(&data[..]);
        if is_comment(&l) {
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
}

fn decode(infile: &str, outfile: &str, passwd: &str) {
    let mut file = File::create(outfile).unwrap();
    for result in BufReader::new(File::open(infile).unwrap()).lines() {
        let l = result.unwrap();
        if is_comment(&l) {
            let _ = writeln!(file, "{}", l);
            continue;
        }
        let caps = Regex::new(r"^([^=]+)=([^:]+):([0-9A-Za-z+/=]+):([^:]*):([0-9A-Za-z+/=]+)$").unwrap().captures(&l).unwrap();
        let y = &base64::decode(caps.get(5).unwrap().as_str()).unwrap();
        let z = crypto::decrypt(caps.get(2).unwrap().as_str(), passwd, caps.get(3).unwrap().as_str(), caps.get(4).unwrap().as_str(), y.to_vec());
        let zz = format!("{}={}", caps.get(1).unwrap().as_str(), z);
        let _ = writeln!(file, "{}", zz);
    }
    file.flush().unwrap();
}

fn print_usage(exe_name: &str, opts: &Options) {
    let brief = format!("Usage: {} REPEAT [Options]", exe_name);
    print!("{}", opts.usage(&brief));
    process::exit(0);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();

    opts.optflag("e", "encode", "encode mode");
    opts.optflag("d", "decode", "decode mode");

    opts.optopt("i", "in", "set input file name", "FILE");
    opts.optopt("o", "out", "set output file name", "FILE");

    opts.optopt("p", "passwd", "password", "PASSWORD");
    opts.optopt("n", "info", "info", "INFO");
    opts.optopt("a", "algo", "algorithm", "ALGORITHM");

    opts.optflag("h", "help", "print this help");

    let matches = opts.parse(&args[1..]).unwrap_or_else(|f| panic!("{}",f.to_string()));

    if matches.opt_present("h") {
        print_usage(&args[0], &opts);
    }

    let input = matches.opt_str("i").unwrap_or_default();
    let output = matches.opt_str("o").unwrap_or_default();
    let passwd = matches.opt_str("p").unwrap_or_default();
    let info = matches.opt_str("n").unwrap_or_default();
    let algo = matches.opt_str("a").unwrap_or_else(|| "sha256-aes128-cbc".to_string());

    if input.is_empty() || output.is_empty() {
        panic!("{}","none file name".to_string());
    }
    if matches.opt_present("e") {
        if !matches.opt_present("d") {
            encode(&input, &output, &passwd, &algo, &info)
        }
        panic!("{}","-e or -d".to_string());
    }
    if matches.opt_present("d") {
        decode(&input, &output, &passwd)
    }
    panic!("{}","-e or -d".to_string());
}
