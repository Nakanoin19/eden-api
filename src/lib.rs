use worker::*;
use serde::Deserialize;
use kryptos::ciphers::{railfence::RailFence, scytale::Scytale};
use widestring::*;
use std::collections::HashMap;
use kanaria::{string::UCSStr, utils::ConvertTarget};
use rayon::prelude::*;
use num_bigint::BigUint;
use num_bigfloat::BigFloat;
use encoding_rs::{self, Encoding};
use fast32;
use b45;
use num::integer::gcd;

/* --------------------
    Type Definition
-------------------- */
#[derive(Deserialize, Clone)]
struct Cipher {
    cipher: String,
    text: Option<String>,
    mode: Option<bool>,
    preset: Option<String>,
    radix: Option<u64>,    // textnum
    base: Option<Base>,    // base
    encoding: Option<String>,    // textnum, base{32, 64, 45}, ascii85
    pad: Option<bool>,    // base{32, 64}
    enctype: Option<String>,    // ascii85
    affine: Option<Affine>,    // affine
    n: Option<i64>,    // caesar, railfence
}

#[derive(Deserialize, Clone, Copy)]
struct Affine {
    a: i64,
    b: i64,
}

#[derive(Deserialize, Clone)]
struct Base {
    aradix: u64,
    bradix: u64,
    apreset: Option<String>,
    bpreset: Option<String>,
    arule: Option<String>,
    brule: Option<String>,
    zero: bool,
}

#[derive(PartialEq)]
enum MorsePreset {
    International,
    JP,
}

#[derive(PartialEq)]
enum WString {
    No,
    Utf16be,
    Utf16le,
    Utf32be,
    Utf32le
}

/* ----------
    Morse
---------- */
const MORSE_JP: [(char, &'static str); 65] = [
    ('ｲ', ".-"),
    ('ﾛ', ".-.-"),
    ('ﾊ', "-..."),
    ('ﾆ', "-.-."),
    ('ﾎ', "-.."),
    ('ﾍ', "."),
    ('ﾄ', "..-.."),
    ('ﾁ', "..-."),
    ('ﾘ', "--."),
    ('ﾇ', "...."),
    ('ﾙ', "-.--."),
    ('ｦ', ".---"),
    ('ﾜ', "-.-"),
    ('ｶ', ".-.."),
    ('ﾖ', "--"),
    ('ﾀ', "-."),
    ('ﾚ', "---"),
    ('ｿ', "---."),
    ('ﾂ', ".--."),
    ('ﾈ', "--.-"),
    ('ﾅ', ".-."),
    ('ﾗ', "..."),
    ('ﾑ', "-"),
    ('ｳ', "..-"),
    ('ヰ', ".-..-"),  // 半角ないので多分そのままで大丈夫だと思いたい
    ('ﾉ', "..--"),
    ('ｵ', ".-..."),
    ('ｸ', "...-"),
    ('ﾔ', ".--"),
    ('ﾏ', "-..-"),
    ('ｹ', "-.--"),
    ('ﾌ', "--.."),
    ('ｺ', "----"),
    ('ｴ', "-.---"),
    ('ﾃ', ".-.--"),
    ('ｱ', "--.--"),
    ('ｻ', "-.-.-"),
    ('ｷ', "-.-.."),
    ('ﾕ', "-..--"),
    ('ﾒ', "-...-"),
    ('ﾐ', "..-.-"),
    ('ｼ', "--.-."),
    ('ヱ', ".--.."),  // 半角ないので多分そのままで大丈夫だと思いたい
    ('ﾋ', "--..-"),
    ('ﾓ', "-..-."),
    ('ｾ', ".---."),
    ('ｽ', "---.-"),
    ('ﾝ', ".-.-."),
    ('\u{ff9e}', ".."), // 濁点
    ('\u{ff9f}', "..--."),  // 半濁点
    ('ｰ', ".--.-"),  // 長音符
    ('､', ".-.-.-"),
    ('｡', ".-.-.."),
    (')', "-.--.-"),
    ('(', ".-..-."),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('0', "-----")
];

const MORSE_INTERNATIONAL: [(char, &'static str); 72] = [
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('0', "-----"),
    ('.', ".-.-.-"),
    (',', "--..--"),
    (':', "---..."),
    ('?', "..--.."),
    ('\\', ".----."),
    ('-', "-....-"),
    ('/', "-..-."),
    ('(', "-.--."),
    (')', "-.--.-"),
    ('"', ".-..-."),
    ('=', "-...-"),
    ('+', ".-.-."),
    ('@', ".--.-."),
    ('!', "-.-.--"),
    ('&', ".-..."),
    (';', "-.-.-."),
    ('_', "..--.-"),
    ('$', "...-..-"),
    ('^', "......"),
    ('À', ".--.-"),
    ('Ä', ".-.-"),
    ('Ć', "-.-.."),
    ('Đ', "..-.."),
    ('Ð', "..--."),
    ('È', ".-..-"),
    ('Ĝ', "--.-."),
    ('Ĥ', "----"),
    ('Ĵ', ".---."),
    ('Ń', "--.--"),
    ('Ó', "---."),
    ('Ś', "...-..."),
    ('Ŝ', "...-."),
    ('Þ', ".--.."),
    ('Ü', "..--"),
    ('Ź', "--..-."),
    ('Ż', "--..-")
];

/* -------------
    REST API
------------- */
#[event(fetch)]
async fn main(mut req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        let mut cors_res = Response::ok("")?;
        cors_res.headers_mut().set("Access-Control-Allow-Origin", "*")?;
        cors_res.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
        cors_res.headers_mut().set("Access-Control-Allow-Headers", "Content-Type")?;
        cors_res.set_status(204);
        return Ok(cors_res);
    }
    let v: Vec<Cipher> = serde_json::from_str(&req.text().await.unwrap()).unwrap();
    let mut text = v[0].text.clone().unwrap_or("".to_string());
    for c in v.into_iter() {
        text = match c.cipher.as_str() {
            "textnum" => textnum(&text, c.mode.unwrap_or(true), c.radix.unwrap(), &c.encoding.unwrap()),
            "morse" => {
                let preset = match c.preset.unwrap_or("".to_string()).as_str() {
                    "international" | "latin" => MorsePreset::International,
                    "ja" | "jp" => MorsePreset::JP,
                    _ => MorsePreset::International,
                };
                morse(&text, c.mode.unwrap_or(true), preset)
            },
            "base" => {
                let makerule = |rule: Option<String>, preset: Option<String>| -> String {
                    if rule == None || rule == Some("".to_string()) {
                        match preset.unwrap_or("".to_string()).as_str() {
                            "36-lower" => "0123456789abcdefghijklmnopqrstuvwxyz",
                            "36-upper" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                            "base32" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                            "base64" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
                            "z85" => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",
                            "adobe-ascii85" => r##"!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu"##,
                            "latin-lower" => "abcdefghijklmnopqrstuvwxyz",
                            "latin-upper" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                            "ml26-lower" => "etianmsurwdkgohvflpjbxcyzq",
                            "ml26-upper" => "ETIANMSURWDKGOHVFLPJBXCYZQ",
                            _ => "0123456789abcdefghijklmnopqrstuvwxyz",
                        }.to_string()
                    } else {
                        rule.unwrap()
                    }
                };
                let arule = makerule(c.clone().base.unwrap().arule, c.clone().base.unwrap().apreset);
                let brule = makerule(c.clone().base.unwrap().brule, c.clone().base.unwrap().bpreset);
                base(&text, c.clone().base.unwrap().bradix, c.clone().base.unwrap().aradix, &brule, &arule, c.base.unwrap().zero)
            },
            "base32" => base32(&text, c.mode.unwrap_or(true), &c.encoding.unwrap_or("".to_string()), c.pad.unwrap_or(true)),
            "base64" => base64(&text, c.mode.unwrap_or(true), &c.encoding.unwrap_or("".to_string()), c.pad.unwrap_or(true)),
            "base45" => base45(&text, c.mode.unwrap_or(true), &c.encoding.unwrap_or("".to_string())),
            "ascii85" => {
                let enctype = if let Some(t) = c.enctype {
                    if ["z85", "adobe", "btoa"].binary_search(&t.as_str()).is_ok() {
                        t
                    } else {
                        "adobe".to_string()
                    }
                } else {
                    "adobe".to_string()
                };
                ascii85(&text, c.mode.unwrap_or(true), &c.encoding.unwrap_or("".to_string()), &enctype)
            },
            "caesar" => caesar(&text, c.mode.unwrap_or(true), c.n.unwrap_or(0)),
            "rot13" => rot13(&text, c.mode.unwrap_or(true)),
            "rot18" => rot18(&text, c.mode.unwrap_or(true)),
            "rot47" => rot47(&text, c.mode.unwrap_or(true)),
            "atbash" => atbash(&text),
            "affine" => affine(&text, c.mode.unwrap_or(true), c.affine.unwrap().a, c.affine.unwrap().b),
            "railfence" => railfence(&text, c.mode.unwrap_or(true), c.n.unwrap_or(0) as u64),
            "scytale" => scytale(&text, c.mode.unwrap_or(true), c.n.unwrap_or(0).abs() as u64),
            _ => text.to_string(),
        };
    };
    Response::ok(text)
}

/* ----------------
    En/Decipher
---------------- */
fn textnum(text: &str, mode: bool, radix: u64, encoding: &str) -> String {  // (true, false) => (encode, decode)
    if radix < 2 || radix > 256 {
        panic!("Invalid radix. Prease set from 2 to 256.");
    }
    let wstring = match encoding {
        "unicodefffe"| "iso-10646-ucs-2be" | "ucs-2be"  | "utf-16be" => WString::Utf16be,
        "csunicode" | "iso-10646-ucs-2" | "ucs-2" | "iso-10646-ucs-2le" | "ucs-2le" | "unicode" | "unicodefeff" |  "utf-16" | "utf-16le" => WString::Utf16le,
        "iso-10646-ucs-4be" | "ucs-4be" |"utf-32be" => WString::Utf32be,
        "iso-10646-ucs-4" | "ucs-4" | "iso-10646-ucs-4le" | "ucs-4le" | "utf-32" | "utf-32le" => WString::Utf32le,
        _ => WString::No
    };
    let encoding = match wstring {
        WString::No => Some(Encoding::for_label_no_replacement(encoding.as_bytes()).unwrap_or_else(|| {
                console_warn!("Invalid encoding.");
                encoding_rs::UTF_8
            })),
        _ => None
    };
    if mode {
        if wstring != WString::No {
            let bytes: Vec<_> = match wstring {
                WString::Utf16be | WString::Utf16le => {
                    let wbytes = encode_utf16(text.chars()).collect::<Vec<_>>();
                    let wbytes_2 = match wstring {
                        WString::Utf16be => wbytes.into_par_iter().map(|c| c.to_be_bytes()).collect::<Vec<_>>(),
                        WString::Utf16le => wbytes.into_par_iter().map(|c| c.to_le_bytes()).collect::<Vec<_>>(),
                        _ => {
                            panic!("It seems some error occurred.");
                        }
                    };
                    wbytes_2.concat()
                },
                WString::Utf32be | WString::Utf32le => {
                    let wbytes = encode_utf32(text.chars()).collect::<Vec<_>>();
                    let wbytes_2 = match wstring {
                        WString::Utf32be => wbytes.into_par_iter().map(|c| c.to_be_bytes()).collect::<Vec<_>>(),
                        WString::Utf32le => wbytes.into_par_iter().map(|c| c.to_le_bytes()).collect::<Vec<_>>(),
                        _ => {
                            panic!("It seems some error occurred.");
                        }
                    };
                    wbytes_2.concat()
                },
                _ => {
                    panic!("It seems some error occurred.");
                }
            };
            let byteslen = BigFloat::parse(&format!("{}", bytes.len())).unwrap();
            let biguint = &BigUint::from_bytes_be(&bytes);
            let st = biguint.to_str_radix(radix as u32);
            let strsize = BigFloat::parse("256.0").unwrap().log(&BigFloat::from_u64(radix)).mul(&byteslen).ceil().to_u128().unwrap() as usize;
            format!("{}{}", "0".repeat(strsize - st.len()), st)
        } else if let Some(_) = encoding {
            let (cow, _, _) = encoding.unwrap().encode(text);  // ない文字はHTMLエスケープに置き換わる
            let bytes = cow.into_par_iter().map(|&c| c).collect::<Vec<u8>>();
            let byteslen = BigFloat::parse(&format!("{}", bytes.len())).unwrap();
            let biguint = &BigUint::from_bytes_be(&bytes);
            let st = biguint.to_str_radix(radix as u32);
            let strsize = BigFloat::parse("256.0").unwrap().log(&BigFloat::from_u64(radix)).mul(&byteslen).ceil().to_u128().unwrap() as usize;
            format!("{}{}", "0".repeat(strsize - st.len()), st)
        } else {
            panic!("It seems some error occurred.");
        }
    } else {
        if wstring != WString::No {
            let mut bytes = BigUint::parse_bytes(text.as_bytes(), radix as u32).unwrap().to_bytes_be();
            match wstring {
                WString::Utf16be | WString::Utf16le => {
                    for _ in 0..(bytes.len() % 2) {
                        bytes.insert(0, 0);
                    }
                    let wbytes_2 = bytes.par_chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<_>>();
                    let wstr = U16Str::from_slice(&wbytes_2);
                    wstr.to_string_lossy()
                },
                WString::Utf32be | WString::Utf32le => {
                    for _ in 0..(bytes.len() % 4) {
                        bytes.insert(0, 0);
                    }
                    let wbytes_2 = bytes.par_chunks(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect::<Vec<_>>();
                    let wstr = U32Str::from_slice(&wbytes_2);
                    wstr.to_string_lossy()
                },
                _ => {
                    panic!("It seems some error occurred.");
                }
            }
        } else if let Some(_) = encoding {
            let bytes = &BigUint::parse_bytes(text.as_bytes(), radix as u32).unwrap().to_bytes_be();
            let (cow, _) = encoding.unwrap().decode_with_bom_removal(bytes);
            format!("{}", cow)
        } else {
            panic!("It seems some error occurred.");
        }
    }
}

fn morse(text: &str, mode: bool, preset: MorsePreset) -> String { // (true, false) => (encode, decode)
    let table_slice: &[(char, &str)] = match preset {
        MorsePreset::International => &MORSE_INTERNATIONAL,
        MorsePreset::JP => &MORSE_JP,
    };
    if mode {
        let text = UCSStr::from_str(text).katakana().narrow(ConvertTarget::ALL).to_string();
        let text = match preset {
            MorsePreset::International => UCSStr::from_str(&morse_international::normalize(&text)).upper_case().to_string(),
            MorsePreset::JP => UCSStr::from_str(&text).to_string().replace("、", "､").replace("。", "｡").replace(".", "｡").replace("\u{ff0e}", "｡").replace(",", "､").replace("\u{ff0c}", "､").replace("゛", "\u{ff9e}").replace("゜", "\u{ff9f}").replace("\u{3099}", "\u{ff9e}").replace("\u{309a}", "\u{ff9f}"),
        };
        let table: HashMap<_, _> = table_slice.par_iter().map(|&c| c).collect();
        let chars = text.chars().collect::<Vec<_>>();
        let tmp = chars.par_iter().map(|c| table.get(c).unwrap_or(&"")).map(|&c| c).collect::<Vec<_>>();
        tmp.join(" ")
    } else {
        let table: HashMap<_, _> = table_slice.into_iter().map(|&c| (c.1, c.0)).collect();
        let chars: Vec<_> = text.split(" ").collect();
        let tmp = chars.par_iter().map(|c| table.get(c).unwrap_or(&'\u{200b}')).map(|&c| c.to_string()).collect::<Vec<_>>();
        UCSStr::from_str(&tmp.join("")).wide(ConvertTarget::KATAKANA).to_string().replace("､", "、").replace("｡", "。").replace("ｰ", "ー").replace("\u{ff9e}", "\u{3099}").replace("\u{ff9f}", "\u{309a}")
    }
}

fn base(text: &str, bradix: u64, aradix: u64, brule: &str, arule: &str, zero: bool) -> String {
    if bradix > 256 || bradix < 2 || aradix > 256 || aradix < 2 {
        panic!("Invalid radix. Prease set from 2 to 256.");
    }
    let strlen = BigFloat::from_u64(bradix).log(&BigFloat::from_u64(aradix)).mul(&BigFloat::parse(&format!("{}", text.len())).unwrap()).ceil().to_u128().unwrap() as usize;
    let vbrule = brule.chars().collect::<Vec<_>>();
    let varule = arule.chars().collect::<Vec<_>>();
    let vbrule_map = vbrule.par_iter().zip(0..(bradix as u8)).collect::<HashMap<_, _>>();
    let varule_map = (0..(aradix as u8)).into_par_iter().zip(varule.par_iter()).collect::<HashMap<_, _>>();
    let chars = text.chars().collect::<Vec<_>>();
    let bnums = chars.par_iter().filter_map(|c| vbrule_map.get(c).ok_or("".to_owned()).ok()).map(|&c| c ).collect::<Vec<_>>();
    let biguint = BigUint::from_radix_be(&bnums, bradix as u32).unwrap();
    let anums = biguint.to_radix_be(aradix as u32);
    let tmp = anums.iter().map(|c| varule_map.get(c).unwrap()).map(|c| c.to_string() ).collect::<Vec<_>>();
    let st = tmp.join("");
    if zero {
        format!("{}{}", "0".repeat(strlen - st.len()), st)
    } else {
        st
    }
}

fn base32(text: &str, mode: bool, encoding: &str, pad: bool) -> String { // (true, false) => (encode, decode)
    if mode {
        let hex = textnum(text, mode, 16, encoding);
        let bytes = utils::hex2bytes(&hex);
        if pad {
            fast32::base32::RFC4648.encode(&bytes)
        } else {
            fast32::base32::RFC4648_NOPAD.encode(&bytes)
        }
    } else {
        let bytes = if pad {
            fast32::base32::RFC4648.decode(text.as_bytes()).unwrap()
        } else {
            fast32::base32::RFC4648_NOPAD.decode(text.as_bytes()).unwrap()
        };
        let hex = utils::bytes2hex(&bytes);
        textnum(&hex, mode, 16, encoding)
    }
}

fn base64(text: &str, mode: bool, encoding: &str, pad: bool) -> String { // (true, false) => (encode, decode)
    if mode {
        let hex = textnum(text, mode, 16, encoding);
        let bytes = utils::hex2bytes(&hex);
        if pad {
            fast32::base64::RFC4648.encode(&bytes)
        } else {
            fast32::base64::RFC4648_NOPAD.encode(&bytes)
        }
    } else {
        let bytes = if pad {
            fast32::base64::RFC4648.decode(text.as_bytes()).unwrap()
        } else {
            fast32::base64::RFC4648_NOPAD.decode(text.as_bytes()).unwrap()
        };
        let hex = utils::bytes2hex(&bytes);
        textnum(&hex, mode, 16, encoding)
    }
}

fn base45(text: &str, mode: bool, encoding: &str) -> String { // (true, false) => (encode, decode)
    if mode {
        let hex = textnum(text, mode, 16, encoding);
        let bytes = utils::hex2bytes(&hex);
        b45::encode_bytes(&bytes)
    } else {
        let bytes = b45::decode_to_bytes(text).unwrap();
        let hex = utils::bytes2hex(&bytes);
        textnum(&hex, mode, 16, encoding)
    }
}

fn ascii85(text: &str, mode: bool, encoding: &str, enctype: &str) -> String {  // (true, false) => (encode, decode)
    let table = match enctype {
        "z85" => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",
        "adobe" | "btoa" => r##"!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu"##,
        _ => { panic!("Invalid type: {}", enctype); }
    };
    let addition = match enctype {
        "z85" => vec![],
        "adobe" => vec![("!!!!!", "z")],
        "btoa" => vec![("!!!!!", "z"), ("+<VdL", "y")],
        _ => { panic!("It seems some error occurred."); }
    }.into_par_iter().map(|(c, d)| (c.to_string(), d.to_string())).collect::<HashMap<_, _>>();

    if mode {
        let hex = textnum(text, mode, 16, encoding);
        let added_bytes = (8 - hex.len() % 8) / 2;
        let hex = format!("{}{}", hex, "0".repeat(added_bytes*2));
        let b85 = hex.chars().collect::<Vec<_>>().chunks(8).map(|c| c.into_iter().collect::<String>()).map(|c| base(&c, 16, 85, "0123456789abcdef", table, false)).map(|c| format!("{:0>5}", c)).collect::<Vec<_>>();
        let tmp = b85.into_par_iter().map(|c| addition.get(&c).unwrap_or(&c).to_owned()).collect::<Vec<_>>().join("");
        match enctype {
            "z85" => tmp.chars().take(tmp.len() - added_bytes).collect::<String>(),  //これでちゃんと期待値になる →解説1
            "adobe" => format!("<~{}~>", tmp.chars().take(tmp.len() - added_bytes).collect::<String>()).chars().collect::<Vec<_>>().chunks(80).map(|c| c.into_par_iter().map(|d| d.to_string()).collect::<Vec<_>>().join("")).collect::<Vec<_>>().join("\n"),
            "btoa" => {
                let byteslen = hex.len() / 2 - added_bytes;
                let mut bytes = BigUint::parse_bytes(hex.as_bytes(), 16).unwrap().to_bytes_be();
                for _ in 0..added_bytes {
                    bytes.pop();
                }
                for _ in 0..(byteslen - bytes.len()) {
                    bytes.insert(0, 0);
                }
                let (mut eor, mut sum, mut rot) = (0usize, 0usize, 0usize);
                for b in bytes.into_iter() {
                    let c = (b & 0xff) as usize;
                    eor ^= c;
                    sum += c + 1;
                    rot <<= 1;
                    if (rot & 0x80000000) != 0 {
                        rot += 1;
                    }
                    rot += c;
                }
                format!("xbtoa Begin\n{}\nxbtoa End N {} {:x} E {:x} S {:x} R {:x}\n", tmp.chars().collect::<Vec<_>>().chunks(80).map(|c| c.into_par_iter().map(|d| d.to_string()).collect::<Vec<_>>().join("")).collect::<Vec<_>>().join("\n"), byteslen, byteslen, eor, sum, rot)
            },
            _ => { panic!("It seems some error occurred."); }
        }
    } else {
        let addition = addition.into_par_iter().map(|c| (c.1, c.0)).collect::<HashMap<_, _>>();
        let added_bytes: usize = match enctype {
            "z85" => 5 - text.len() % 5, // これでちゃんと期待値になる →解説1
            "adobe" => 5 - (text.lines().collect::<Vec<_>>().join("").len() - 4 + text.match_indices("z").count() * 4) % 5,
            "btoa" => {
                let spl = text.trim().lines().collect::<Vec<_>>();
                let bytesnum = spl[spl.len()-1].split_whitespace().nth(3).unwrap().parse::<usize>().unwrap();
                4 - bytesnum % 4
            },
            _ => { panic!("It seems some error occurred."); }
        };
        let text = match enctype {
            "z85" => format!("{}{}", text, "#".repeat(added_bytes)),
            "adobe" => {
                let t = text.lines().collect::<Vec<_>>().join("");
                format!("{}{}", t.chars().skip(2).take(t.len()-4).map(|c| c.to_string()).collect::<Vec<_>>().join(""), "u".repeat(added_bytes))
            },
            "btoa" => {
                let spl = text.trim().lines().collect::<Vec<_>>();
                spl.par_iter().skip(1).take(spl.len()-2).map(|&c| c).collect::<Vec<_>>().join("")
            }
            _ => { panic!("It seems some error occurred."); }
        };
        let before_add = text.chars().map(|c| addition.get(&c.to_string()).unwrap_or(&c.to_string()).to_string()).collect::<Vec<_>>().join("");
        let tmp = before_add.chars().collect::<Vec<_>>().chunks(5).map(|c| c.into_iter().collect::<String>()).map(|c| base(&c, 85, 16, table, "0123456789abcdef", false)).map(|c| format!("{:0>8}", c)).collect::<Vec<_>>().join("");
        let hex = tmp.chars().take(tmp.len() - added_bytes * 2).collect::<String>();
        textnum(&hex, mode, 16, encoding)
    }
    
    /*
    解説s
        1. なんでlog使わずに期待値通りになるの?
            4バイトで区切るので0でパディングしたバイト数が1, 2, 3Bのときのみみればよい
            log_85(256)  ≈ 1.25
            2log_85(256) ≈ 2.50
            3log_85(256) ≈ 3.74
            整数部分までで切り下げたときにバイト数と等しくなるから
    */
}

fn caesar(text: &str, mode: bool, n: i64) -> String {  // (true, false) => (encode, decode)
    let make_map = |cs: &[char]| -> HashMap<char, usize> {
        cs.par_iter().map(|&c| c).enumerate().map(|c| (c.1, c.0)).collect::<HashMap<_, _>>()
    };
    let latin_u = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect::<Vec<_>>();
    let latin_l = "abcdefghijklmnopqrstuvwxyz".chars().collect::<Vec<_>>();
    let cyrillic_u = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ".chars().collect::<Vec<_>>();
    let cyrillic_l = "абвгдежзийклмнопрстуфхцчшщъыьэюя".chars().collect::<Vec<_>>();
    let kana_hira = "ぁあぃいぅうぇえぉおかがきぎくぐけげこごさざしじすずせぜそぞただちぢっつづてでとどなにぬねのはばぱひびぴふぶぷへべぺほぼぽまみむめもゃやゅゆょよらりるれろゎわゐゑをんゔ".chars().collect::<Vec<_>>();
    let kana_kata = "ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロヮワヰヱヲンヴ".chars().collect::<Vec<_>>();
    let num = "0123456789".chars().collect::<Vec<_>>();
    let swap = |st: String, table: &[char]| -> String {
        st.par_chars().map(|c| match make_map(table).get(&c) {
            Some(&i) => table[(((i as i64 + (if mode { n } else { -n }) % table.len() as i64) + table.len() as i64) % table.len() as i64) as usize],
            None => c
        }).collect::<String>()
    };
    let latin_u_ed = swap(text.to_string(),&latin_u);
    let latin_l_ed = swap(latin_u_ed, &latin_l);
    let cyrillic_u_ed = swap(latin_l_ed, &cyrillic_u);
    let cyrillic_l_ed = swap(cyrillic_u_ed, &cyrillic_l);
    let kana_hira_ed = swap(cyrillic_l_ed, &kana_hira);
    let kana_kata_ed = swap(kana_hira_ed, &kana_kata);
    let num_ed = swap(kana_kata_ed, &num);
    num_ed
}

fn rot13(text: &str, mode: bool) -> String {  // (true, false) => (encode, decode)
    let is_latin = |ch: char| -> bool {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(&ch.to_string())
    };
    text.par_chars().map(|c| if is_latin(c) { caesar(&c.to_string(), mode, 13) } else { c.to_string() }).collect::<Vec<_>>().join("")
}

fn rot18(text: &str, mode: bool) -> String {  // (true, false) => (encode, decode)
    let is_latin = |ch: char| -> bool {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(&ch.to_string())
    };
    let is_num = |ch: char| -> bool {
        "0123456789".contains(&ch.to_string())
    };
    text.par_chars().map(|c| if is_latin(c) { caesar(&c.to_string(), mode, 13) } else if is_num(c) { caesar(&c.to_string(), mode, 5) } else { c.to_string() }).collect::<Vec<_>>().join("")
}

fn rot47(text: &str, mode: bool) -> String {  // (true, false) => (encode, decode)
    let table = r##"!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"##.chars().collect::<Vec<_>>();
    let map = table.par_iter().map(|&c| c).enumerate().map(|c| (c.1, c.0)).collect::<HashMap<_, _>>();
    text.par_chars().map(|c| match map.get(&c) {
        Some(&i) => table[(((i as i64 + (if mode { 47 } else { -47 }) as i64 % 94 as i64) + 94 as i64) % 94 as i64) as usize],
        None => c
    }).collect::<String>()
}

fn atbash(text: &str) -> String {
    let make_map = |cs: Vec<char>| -> HashMap<char, char> {
        cs.par_iter().zip(cs.par_iter().rev()).map(|(&i0, &i1)| (i0, i1)).collect::<HashMap<_, _>>()
    };
    let latin_u = make_map("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect::<Vec<_>>());
    let latin_l = make_map("abcdefghijklmnopqrstuvwxyz".chars().collect::<Vec<_>>());
    let cyrillic_u = make_map("АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ".chars().collect::<Vec<_>>());
    let cyrillic_l = make_map("абвгдежзийклмнопрстуфхцчшщъыьэюя".chars().collect::<Vec<_>>());
    let kana_hira = make_map("ぁあぃいぅうぇえぉおかがきぎくぐけげこごさざしじすずせぜそぞただちぢっつづてでとどなにぬねのはばぱひびぴふぶぷへべぺほぼぽまみむめもゃやゅゆょよらりるれろゎわゐゑをんゔ".chars().collect::<Vec<_>>());
    let kana_kata = make_map("ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロヮワヰヱヲンヴ".chars().collect::<Vec<_>>());
    let hebrew = make_map("אבגדהוזחטיכלמנסעפצקרשת".chars().collect::<Vec<_>>());
    let swap = |st: String, map: HashMap<char, char>| -> String {
        st.chars().map(|c| match map.get(&c) {
            Some(&i) => i,
            None => c
        }).collect::<String>()
    };
    let latin_u_ed = swap(text.to_string(), latin_u);
    let latin_l_ed = swap(latin_u_ed, latin_l);
    let cyrillic_u_ed = swap(latin_l_ed, cyrillic_u);
    let cyrillic_l_ed = swap(cyrillic_u_ed, cyrillic_l);
    let kana_hira_ed = swap(cyrillic_l_ed, kana_hira);
    let kana_kata_ed = swap(kana_hira_ed, kana_kata);
    let hebrew_ed = swap(kana_kata_ed, hebrew);
    hebrew_ed
}

fn affine(text: &str, mode: bool, a: i64, b: i64) -> String {  // (true, false) => (encode, decode)
    let make_map = |cs: &[char]| -> HashMap<char, usize> {
        cs.par_iter().map(|&c| c).enumerate().map(|c| (c.1, c.0)).collect::<HashMap<_, _>>()
    };
    let latin_u = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect::<Vec<_>>();
    let latin_l = "abcdefghijklmnopqrstuvwxyz".chars().collect::<Vec<_>>();
    let cyrillic_u = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ".chars().collect::<Vec<_>>();
    let cyrillic_l = "абвгдежзийклмнопрстуфхцчшщъыьэюя".chars().collect::<Vec<_>>();
    let kana_hira = "ぁあぃいぅうぇえぉおかがきぎくぐけげこごさざしじすずせぜそぞただちぢっつづてでとどなにぬねのはばぱひびぴふぶぷへべぺほぼぽまみむめもゃやゅゆょよらりるれろゎわゐゑをんゔ".chars().collect::<Vec<_>>();
    let kana_kata = "ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロヮワヰヱヲンヴ".chars().collect::<Vec<_>>();
    let swap = |st: String, table: &[char], cp: bool, minv: i64| {
        st.chars().map(|c| match make_map(table).get(&c) {
            Some(&i) => if mode {
                if cp {
                    table[((a * i as i64 + b) % table.len() as i64 + table.len() as i64) as usize % table.len()]
                } else {
                    c
                }
            } else {
                if minv == 0 {
                    c
                } else {
                    table[((minv * (i as i64 - b)) % table.len() as i64 + table.len() as i64) as usize % table.len()]
                }
            },
            None => c
        }).collect::<String>()
    };
    let modinv = |l: i64| -> i64 {
        let an = a % l;
        if gcd(an.abs(), l) != 1 {
            return 0;
        }
        for x in 1..l {
            if (an.abs() * x) % l == 1 {
                return x * (if a < 0 { -1 } else { 1 });
            }
        }
        0
    };
    let is_coprime = |l: i64| -> bool {
        gcd(a.abs(), l) == 1
    };
    let latin_u_ed = swap(text.to_string(), &latin_u, is_coprime(26), modinv(26));
    let latin_l_ed = swap(latin_u_ed, &latin_l, is_coprime(26), modinv(26));
    let cyrillic_u_ed = swap(latin_l_ed, &cyrillic_u, is_coprime(32), modinv(32));
    let cyrillic_l_ed = swap(cyrillic_u_ed, &cyrillic_l, is_coprime(32), modinv(32));
    let kana_hira_ed = swap(cyrillic_l_ed, &kana_hira, is_coprime(84), modinv(84));
    let kana_kata_ed = swap(kana_hira_ed, &kana_kata, is_coprime(84), modinv(84));
    kana_kata_ed
}

fn railfence(text: &str, mode: bool, n: u64) -> String {  // (true, false) => (encode, decode)
    let r = RailFence::new(n as usize).unwrap();
    if mode {
        r.encipher(text).unwrap()
    } else {
        r.decipher(text).unwrap()
    }
}

fn scytale(text: &str, mode: bool, n: u64) -> String {  // (true, false) => (encode, decode)
    let s = Scytale::new(n as usize).unwrap();
    if mode {
        s.encipher(text).unwrap()
    } else {
        s.decipher(text).unwrap()
    }
}

/* ----------
    Tests
---------- */
#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn textnum_test() {
        assert_eq!(textnum(&textnum("うわ〜", true, 16, "utf-16be"), false, 16, "utf-16be"), "うわ〜");
        assert_eq!(textnum(&textnum("うわ〜", true, 16, "sjis"), false, 16, "sjis"), "うわ&#12316;".to_string())
    }
    #[test]
    fn morse_test() {
        assert_eq!(morse(&morse("がき゛く\u{3099}け゜こ\u{309a}", true, MorsePreset::JP), false, MorsePreset::JP), "ガギグケ\u{309a}コ\u{309a}".to_string());
        assert_eq!(morse(&morse("ƿynn", true, MorsePreset::International), false, MorsePreset::International), "WYNN".to_string());
    }
    #[test]
    fn base_test() {
        let ml26 = "ETIANMSURWDKGOHVFLPJBXCYZQ";
        let b16 = "0123456789abcdef";
        assert_eq!(base("THE QUICK BROWN FOX JUMPS OVER THE LAGY DOG", 26, 16, ml26, b16, false), "15ac21ffabd7bd5e78c3c53b1c48ab8de14bf40be".to_string());
    }
    #[test]
    fn rfc4648_test() {
        assert_eq!(base32(&base32("うわ〜", true, "utf-8", true), false, "utf-8", true), base64(&base64("うわ〜", true, "utf-8", true), false, "utf-8", true));
    }
    #[test]
    fn base45_test() {
        assert_eq!(base45(&base45("うわ〜", true, "utf-8"), false, "utf-8"), "うわ〜".to_string());
    }
    #[test]
    fn ascii85_test() {
        assert_eq!(ascii85(&ascii85("あいうえお", true, "utf-8", "z85"), false, "utf-8", "z85"), "あいうえお".to_string());
        assert_eq!(ascii85(&ascii85("あいうえお", true, "utf-8", "adobe"), false, "utf-8", "adobe"), "あいうえお".to_string());
        assert_eq!(ascii85(&ascii85("あいうえお", true, "utf-8", "btoa"), false, "utf-8", "btoa"), "あいうえお".to_string());
    }
    #[test]
    fn caesar_test() {
        assert_eq!(caesar("あいうえお", true, 2), "いうえおが".to_string());
    }
    #[test]
    fn rotn_test() {
        assert_eq!(rot13("AbCdEfG", true), rot13("AbCdEfG", false));
        assert_eq!(rot18("AbCdEfG01234", true), rot18("AbCdEfG01234", false));
        assert_eq!(rot47("qaWSedRFtgYHujIKolP0123456789", true), rot47("qaWSedRFtgYHujIKolP0123456789", false));
    }
    #[test]
    fn atbash_test() {
        assert_eq!(atbash(&atbash("あいうえおABcde")), "あいうえおABcde".to_string());
    }
    #[test]
    fn affine_test() {
        assert_eq!(affine(&affine("なにこれNanikore", true, 5, 3), false, 5, 3), "なにこれNanikore".to_string());
    }
    #[test]
    fn railfence_test() {
        assert_eq!(railfence(&railfence("あいうえお", true, 3), false, 3), "あいうえお".to_string());
    }
}

/* ----------
    Utils
---------- */
mod morse_international {
    use std::collections::HashMap;
    use rayon::prelude::*;

    pub fn normalize(text: &str) -> String {
        let mut map = HashMap::new();
        map.insert('Ƿ', 'W');
        map.insert('ƿ', 'W');
        map.insert('\u{00d7}', 'X'); // 乗算記号
        map.insert('à', 'À');
        map.insert('Å', 'À');
        map.insert('å', 'À');
        map.insert('ä', 'Ä');
        map.insert('Æ', 'Ä');
        map.insert('æ', 'Ä');
        map.insert('Ą', 'Ä');
        map.insert('ą', 'Ä');
        map.insert('ć', 'Ć');
        map.insert('Ĉ', 'Ć');
        map.insert('ĉ', 'Ć');
        map.insert('Ç', 'Ć');
        map.insert('ç', 'Ć');
        map.insert('đ', 'Đ');
        map.insert('É', 'Đ');
        map.insert('é', 'Đ');
        map.insert('Ę', 'Đ');
        map.insert('ę', 'Đ');
        map.insert('ð', 'Ð');
        map.insert('è', 'È');
        map.insert('Ł', 'È');
        map.insert('ł', 'È');
        map.insert('ĝ', 'Ĝ');
        map.insert('ĥ', 'Ĥ');
        map.insert('Š', 'Ĥ');
        map.insert('š', 'Ĥ');
        map.insert('ĵ', 'Ĵ');
        map.insert('ń', 'Ń');
        map.insert('Ñ', 'Ń');
        map.insert('ñ', 'Ń');
        map.insert('ó', 'Ó');
        map.insert('Ö', 'Ó');
        map.insert('ö', 'Ó');
        map.insert('Ø', 'Ó');
        map.insert('ø', 'Ó');
        map.insert('ś', 'Ś');
        map.insert('ŝ', 'Ŝ');
        map.insert('þ', 'Þ');
        map.insert('ü', 'Ü');
        map.insert('Ŭ', 'Ü');
        map.insert('ŭ', 'Ü');
        map.insert('ź', 'Ź');
        map.insert('ż', 'Ż');
        let chars = text.chars().collect::<Vec<_>>();
        let tmp = chars.par_iter().map(|c| map.get(c).unwrap_or(c)).map(|&c| c.to_string()).collect::<Vec<_>>();
        tmp.join("")
    }
}

mod utils {
    use num_bigint::BigUint;
    
    pub fn hex2bytes(hex: &str) -> Vec<u8> {
        let byteslen = hex.len() / 2;
        let mut bytes = BigUint::parse_bytes(hex.as_bytes(), 16).unwrap().to_bytes_be();
        for _ in 0..(byteslen - bytes.len()) {
            bytes.insert(0, 0);
        }
        bytes
    }

    pub fn bytes2hex(bytes: &[u8]) -> String {
        let hexlen = bytes.len() * 2;
        let hex = BigUint::from_bytes_be(bytes).to_str_radix(16);
        format!("{}{}", "0".repeat(hexlen - hex.len()), hex)
    }
}
