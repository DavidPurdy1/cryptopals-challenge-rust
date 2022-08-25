use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::str;
use std::u8;
use std::fs;
use hex;

// Convert hex to base64
fn challenge1() {
    let data = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let bytes = htov(data);
    let result = base64encode(bytes);
    assert_eq!(
        result,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
}

// 2 equal length strings and xors them
fn challenge2() {
    let s1 = String::from("1c0111001f010100061a024b53535009181c");
    let s2 = String::from("686974207468652062756c6c277320657965");

    // Convert to vectors of bytes to xor values
    let v1 = htov(s1);
    let v2 = htov(s2);

    let result = xor_strings(v1, v2);
    assert_eq!(result, "the kid don't play")
}

// Find the key and decrypt the message
fn challenge3() {
    let s1 = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let v1 = htov(s1);
    check_xor_encrypted(&v1);
}

// check if u8 vector passed in is xor encrypted, only print out readable strings
fn check_xor_encrypted(vec: &[u8]) {
    // loop over all ascii characters for the key
    for letter in 0..255 {
        let result: Vec<u8> = reverse_single_byte_xor(&vec, letter);
        let s = match str::from_utf8(&result) {
            Ok(v) => v,
            Err(e) => "", // umm just skip error messages, filter out below
        };
        if !s.is_empty() {
            if s.chars()
                .all(|x: char| x.is_alphanumeric() || x.is_whitespace())
            {
                println!("{}", s);
            }
        }
    }
}

// ONE of the 60 char strings is single char xor encrypted, find and decrypt
fn challenge4() {
    // Challenge 4 is removing punctuation and challenge 3 needs punctuation
    let file: File = match File::open("single_line_xor_encrypted.txt") {
        Ok(f) => f,
        Err(e) => panic!("Problem opening file: {:?}", e),
    };

    let reader = BufReader::new(file);

    // check each line if it is xor encrypted
    for line in reader.lines() {
        let s: String = match line {
            Ok(s) => s,
            Err(e) => panic!("Problem reading file: {:?}", e),
        };
        let v: Vec<u8> = htov(s);
        check_xor_encrypted(&v);
    }
}

fn challenge5() {
    let key: String = String::from("ICE");
    let text: String = String::from(
        "Burning 'em, if you ain't quick and nimble
        I go crazy when I hear a cymbal",
    );

    println!("{}", repeating_key_xor(&text, &key));
}

// breaking a repeated xor key (also called a vigenere key)
fn challenge6() {
    // Ensure that hamming distance works
    let b1: &[u8] = "this is a test".as_bytes();
    let b2: &[u8] ="wokka wokka!!!".as_bytes();
    assert_eq!(hamming_distance(&b1, &b2), 37);

    let file_contents: String = match fs::read_to_string("6.txt") {
        Ok(s) => s,
        Err(e) => panic!("Failed to read the file {}", e),
    };

    let decoded_file = base64decode(htov(file_contents));
    
    // lets guess a random key up to length 40
    for keysize in 2..40 {

        
    }


}

// difference in bytes of 2 strings
fn hamming_distance(v1: &[u8], v2: &[u8]) -> i32 {
    let mut count = 0;

    if v1.len() != v2.len() {
        return -1;
    }

    // a lil silly, count up all the 1s 
    for bytes in v1.iter().zip(v2.iter()) {
        for c in format!("{:b}", bytes.0 ^ bytes.1).chars() {
            if c == '1' {
                count += 1;
            }
        }
    }

    return count;
}

fn transpose(){

}

// given a key it is going to repeatedly xor the keys bytes with each byte of the string
fn repeating_key_xor(text: &String, key: &String) -> String {
    let mut result:Vec<u8> = Vec::new();
    let mut keyidx: usize = 0;
    let key: &[u8] = key.as_bytes();
    let keylen: usize = key.len();

    for byte in text.as_bytes(){
        result.push(byte ^ key[keyidx % keylen]);
        keyidx += 1;
    }
    return vtoh(result)//converts vec<u8> to a hex string
}


// Wrappers for rust crates used

// Get a hexstring and convert it to an array of u8s
fn old_htov(hex: String) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..(hex.len() / 2) {
        let res = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16);
        match res {
            Ok(v) => bytes.push(v),
            Err(e) => println!("Problem with hex: {}", e),
        };
    }
    bytes
}

// Convert hex string to bytes vec
fn htov(hex: String) -> Vec<u8> {
    return match hex::decode(hex) {
        Ok(v) => v,
        Err(e) => panic!("Failed hex string to vec, this shouldn't happen {}", e),
    };
}

// Convert a bytes vec to hex string
fn vtoh(vec: Vec<u8>) -> String {
    return hex::encode(vec); 
}

fn base64decode(v: Vec<u8>) -> Vec<u8>{
    return match base64::decode(v) {
        Ok(v) => v,
        Err(e) => panic!("Base64 library failed to decrypt {}", e),
    };
}

fn base64encode(v: Vec<u8>) -> String {
    return base64::encode(v);
}

// xor strings together and return value
fn xor_strings(v1: Vec<u8>, v2: Vec<u8>) -> String {
    let result = v1.iter().zip(v2.iter()).map(|(&b1, &b2)| b1 ^ b2).collect();
    return String::from_utf8(result).expect("Invalid byte string");
}

// take the string and xor every byte against the letter
fn reverse_single_byte_xor(v1: &[u8], letter: u8) -> Vec<u8> {
    return v1.iter().map(|byte| byte ^ letter).collect();
}

pub fn runall() {
    challenge1();
    challenge2();
    //challenge3();
    //challenge4();
    //challenge5();
    challenge6();
}
