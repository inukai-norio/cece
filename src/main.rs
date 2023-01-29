extern crate getopts;

use getopts::Options;
use std::env;
use std::process;
use std::fs::File;
use std::io::{BufRead, BufReader, Write, BufWriter};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_std};

static CSP_RNG: Lazy<Mutex<ChaCha20Rng>> = Lazy::new(|| {
    let csp_rng = ChaCha20Rng::from_entropy();
    Mutex::new(csp_rng)
});

struct EncodeCaps<'t> {
    name: &'t str,
    data: &'t str,
}

impl EncodeCaps<'_> {
    fn new(input: &str) -> EncodeCaps {
        let caps = Regex::new(r"^([^=]+)=(.*)$").unwrap().captures(input).unwrap();

        EncodeCaps {
            name: caps.get(1).unwrap().as_str(),
            data: caps.get(2).unwrap().as_str(),
        }
    }
}

struct DecodeCaps<'t> {
    name: &'t str,
    algo: &'t str,
    salt: &'t str,
    info: &'t str,
    data: &'t str,
}

impl DecodeCaps<'_> {
    fn new(input: &str) -> DecodeCaps {
        let caps = Regex::new(r"^([^=]+)=([^:]+):([0-9A-Za-z+/=]+):([^:]*):([0-9A-Za-z+/=]+)$").unwrap().captures(input).unwrap();

        DecodeCaps {
            name: caps.get(1).unwrap().as_str(),
            algo: caps.get(2).unwrap().as_str(),
            salt: caps.get(3).unwrap().as_str(),
            info: caps.get(4).unwrap().as_str(),
            data: caps.get(5).unwrap().as_str(),
        }
    }
}

mod crypto;

fn is_comment(l: &str) -> bool {
    Regex::new(r"^(#.*|\s*)$").unwrap().is_match(l)
}

fn encode(infile: &str, outfile: &str, passwd: &str, algo: &str, info: &str) {
    let instream = BufReader::new(File::open(infile).unwrap());
    let mut outstream = BufWriter::new(File::create(outfile).unwrap());

    for result in instream.lines() {
        let res = result.unwrap();

        if is_comment(&res) {
            let _ = writeln!(outstream, "{res}");
            continue;
        }

        let _ = writeln!(outstream, "{}", encode_line(&res, passwd, algo, info));
    }
    outstream.flush().unwrap();
}

fn encode_line(input: &str, passwd: &str, algo: &str, info: &str) -> String{
    let mut data = [0u8; 32];
    CSP_RNG.lock().unwrap().fill_bytes(&mut data);

    let salt = &base64_std.encode(&data[..]);
    let caps = EncodeCaps::new(input);

    let encrypted_string = crypto::encrypt(algo, passwd, salt, info, caps.data);
    let encoded_string = base64_std.encode(&encrypted_string[..]);

    format!("{}={}:{}:{}:{}", caps.name, algo, salt, info, encoded_string)
}

fn decode(infile: &str, outfile: &str, passwd: &str) {
    let instream = BufReader::new(File::open(infile).unwrap());
    let mut outstream = BufWriter::new(File::create(outfile).unwrap());

    for result in instream.lines() {
        let res = result.unwrap();

        if is_comment(&res) {
            let _ = writeln!(outstream, "{res}");
            continue;
        }

        let _ = writeln!(outstream, "{}", decode_line(&res, passwd));
    }
    outstream.flush().unwrap();
}

fn decode_line(input: &str, passwd: &str) -> String{
    let caps = DecodeCaps::new(input);

    let decoded_string = base64_std.decode(caps.data).unwrap();
    let decrypted_string = crypto::decrypt(caps.algo, passwd, caps.salt, caps.info, decoded_string.to_vec());

    format!("{}={}", caps.name, decrypted_string)
}

fn print_usage(exe_name: &str, opts: &Options) {
    let brief = format!("Usage: {exe_name} REPEAT [Options]");
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
            return encode(&input, &output, &passwd, &algo, &info);
        }
        panic!("{}","-e or -d".to_string());
    }
    if matches.opt_present("d") {
        return decode(&input, &output, &passwd);
    }
    panic!("{}","-e or -d".to_string());
}
