use base64::{decode,encode};
use byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use cryptonum::unsigned::{Decoder,Encoder};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
#[cfg(test)]
use std::io::Cursor;
#[cfg(test)]
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::iter::Iterator;

const OPENER: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
const CLOSER: &'static str = "-----END OPENSSH PRIVATE KEY-----";

pub fn parse_ssh_private_key_data(s: &str) -> Result<Vec<u8>,SSHKeyParseError>
{
    if s.starts_with(OPENER) {
        if let Some(endidx) = s.find(CLOSER) {
            let b64str: String = s[OPENER.len()..endidx].chars().filter(|x| *x != '\n').collect();
            let bytes = decode(&b64str)?;
            Ok(bytes)
        } else {
            Err(SSHKeyParseError::NoEndBannerFound)
        }
    } else {
        Err(SSHKeyParseError::NoBeginBannerFound)
    }
}

pub fn render_ssh_private_key_data(bytes: &[u8]) -> String
{
    let mut bytestr = encode(bytes);
    let mut output = String::new();

    output.push_str(OPENER);
    while bytestr.len() > 70 {
        let rest = bytestr.split_off(70);
        output.push_str(&bytestr);
        output.push_str("\n");
        bytestr = rest;
    }
    output.push_str(&bytestr);
    output.push_str("\n");
    output.push_str(CLOSER);

    output
}

//------------------------------------------------------------------------------

const OPENSSH_MAGIC_HEADER: &'static str = "openssh-key-v1\0";
const OPENSSH_MAGIC_HEADER_LEN: usize = 15;

pub fn parse_openssh_header<R: Read>(input: &mut R) -> Result<(),SSHKeyParseError>
{
    let mut limited_input_header = input.take(OPENSSH_MAGIC_HEADER_LEN as u64);
    let mut header: [u8; OPENSSH_MAGIC_HEADER_LEN] = [0; OPENSSH_MAGIC_HEADER_LEN];

    assert_eq!(OPENSSH_MAGIC_HEADER.len(), OPENSSH_MAGIC_HEADER_LEN);
    limited_input_header.read_exact(&mut header)?;

    for (left, right) in OPENSSH_MAGIC_HEADER.bytes().zip(header.iter()) {
        if left != *right {
            return Err(SSHKeyParseError::NoOpenSSHMagicHeader)
        }

    }

    Ok(())
}

pub fn render_openssh_header<O: Write>(output: &mut O) -> Result<(),SSHKeyRenderError>
{
    Ok(output.write_all(OPENSSH_MAGIC_HEADER.as_bytes())?)
}

//------------------------------------------------------------------------------

pub fn parse_openssh_u32<I: Read>(input: &mut I) -> Result<u32,SSHKeyParseError>
{
    let mut limited_input_header = input.take(4);
    let res = limited_input_header.read_u32::<BigEndian>()?;
    Ok(res)
}

pub fn render_openssh_u32<O: Write>(output: &mut O, val: u32) -> Result<(),SSHKeyRenderError>
{
    Ok(output.write_u32::<BigEndian>(val)?)
}

//------------------------------------------------------------------------------

pub fn parse_openssh_string<I: Read>(input: &mut I) -> Result<String,SSHKeyParseError>
{
    let length = parse_openssh_u32(input)?;
    println!("len: {:X}", length);
    let mut limited_input = input.take(length as u64);
    let mut result = String::new();
    limited_input.read_to_string(&mut result)?;
    Ok(result)
}

pub fn render_openssh_string<O: Write>(output: &mut O, v: &str) -> Result<(),SSHKeyRenderError>
{
    let vbytes: Vec<u8> = v.bytes().collect();
    let len = vbytes.len();
    
    if len > 0xFFFFFFFF {
        return Err(SSHKeyRenderError::StringTooLong);
    }

    render_openssh_u32(output, vbytes.len() as u32)?;
    output.write_all(&vbytes)?;
    Ok(())
}

//------------------------------------------------------------------------------

pub fn parse_openssh_buffer<I: Read>(input: &mut I) -> Result<Vec<u8>,SSHKeyParseError>
{
    let length = parse_openssh_u32(input)?;
    let mut limited_input = input.take(length as u64);
    let mut res = Vec::with_capacity(length as usize);
    limited_input.read_to_end(&mut res)?;
    Ok(res)
}

pub fn render_openssh_buffer<O: Write>(output: &mut O, b: &[u8]) -> Result<(),SSHKeyRenderError>
{
    if b.len() > 0xFFFFFFFF {
        return Err(SSHKeyRenderError::BufferTooLarge);
    }

    render_openssh_u32(output, b.len() as u32)?;
    if b.len() > 0 {
        output.write_all(b)?;
    }

    Ok(())
}

//------------------------------------------------------------------------------

pub fn parse_openssh_number<I,D>(input: &mut I) -> Result<D,SSHKeyParseError>
 where
  I: Read,
  D: Decoder
{
    let mut buffer = parse_openssh_buffer(input)?;
    while buffer[0] == 0 { buffer.remove(0); }
    Ok(D::from_bytes(&buffer))
}

pub fn render_openssh_number<O,D>(output: &mut O, n: &D) -> Result<(),SSHKeyRenderError>
 where
  O: Write,
  D: Encoder
{
    let bytes = n.to_bytes();
    render_openssh_buffer(output, &bytes)
}

//------------------------------------------------------------------------------

#[cfg(test)]
use cryptonum::unsigned::{U192,U1024,U2048,U4096};

#[cfg(test)]
quickcheck! {
    fn bytes_roundtrip(x: Vec<u8>) -> bool {
        let rendered = render_ssh_private_key_data(&x);
        let returned = parse_ssh_private_key_data(&rendered).unwrap();
        returned == x
    }

    fn blocks_formatted(x: Vec<u8>) -> bool {
        let rendered = render_ssh_private_key_data(&x);
        let mut is_ok = true;

        for line in rendered.lines() {
            is_ok &= line.len() <= 70;
        }

        is_ok
    }

    fn u32s_roundtrip_rp(x: u32) -> bool {
        let mut buffer = vec![];
        render_openssh_u32(&mut buffer, x).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check = parse_openssh_u32(&mut cursor).unwrap();
        x == check
    }

    fn u32s_roundtrip_pr(a: u8, b: u8, c: u8, d: u8) -> bool {
        let block = [a,b,c,d];
        let mut cursor = Cursor::new(block);
        let base = parse_openssh_u32(&mut cursor).unwrap();
        let mut rendered = vec![];
        render_openssh_u32(&mut rendered, base).unwrap();
        (block[0] == rendered[0]) &&
        (block[1] == rendered[1]) &&
        (block[2] == rendered[2]) &&
        (block[3] == rendered[3])
    }

    fn string_roundtrip(s: String) -> bool {
        let mut buffer = vec![];
        render_openssh_string(&mut buffer, &s).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check = parse_openssh_string(&mut cursor).unwrap();
        s == check
    }

    fn buffer(os: Vec<u8>) -> bool {
        let mut buffer = vec![];
        render_openssh_buffer(&mut buffer, &os).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check = parse_openssh_buffer(&mut cursor).unwrap();
        os == check
    }

    fn u192(x: U192) -> bool {
        let mut buffer = vec![];
        render_openssh_number(&mut buffer, &x).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check: U192 = parse_openssh_number(&mut cursor).unwrap();
        check == x
    }

    fn u1024(x: U1024) -> bool {
        let mut buffer = vec![];
        render_openssh_number(&mut buffer, &x).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check: U1024 = parse_openssh_number(&mut cursor).unwrap();
        check == x
    }

    fn u2048(x: U2048) -> bool {
        let mut buffer = vec![];
        render_openssh_number(&mut buffer, &x).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check: U2048 = parse_openssh_number(&mut cursor).unwrap();
        check == x
    }

    fn u4096(x: U4096) -> bool {
        let mut buffer = vec![];
        render_openssh_number(&mut buffer, &x).unwrap();
        let mut cursor = Cursor::new(buffer);
        let check: U4096 = parse_openssh_number(&mut cursor).unwrap();
        check == x
    }
}

#[cfg(test)]
#[test]
fn pregenerated_reencode() {
    let test_files = ["dsa1024-1", "dsa1024-2", "dsa1024-3",
                      "ecdsa256-1", "ecdsa256-2", "ecdsa256-3",
                      "ecdsa384-1", "ecdsa384-2", "ecdsa384-3",
                      "ecdsa521-1", "ecdsa521-2", "ecdsa521-3",
                      "ed25519-1", "ed25519-2", "ed25519-3",
                      "rsa1024-1", "rsa1024-2", "rsa1024-3",
                      "rsa2048-1", "rsa2048-2", "rsa2048-3",
                      "rsa3072-1", "rsa3072-2", "rsa3072-3",
                      "rsa4096-1", "rsa4096-2", "rsa4096-3",
                      "rsa8192-1", "rsa8192-2", "rsa8192-3" ];

    for file in test_files.iter() {
        let path = format!("testdata/ssh/{}",file);
        let mut fd = File::open(path).unwrap();
        let mut contents = String::new();
        fd.read_to_string(&mut contents).unwrap();
        let parsed = parse_ssh_private_key_data(&contents).unwrap();
        let rendered = render_ssh_private_key_data(&parsed);
        // starts_with() avoids newline unpleasantness
        assert!(contents.starts_with(&rendered));
    }
}

#[cfg(test)]
#[test]
fn header_roundtrips() {
    let mut vec = Vec::new();
    assert!(render_openssh_header(&mut vec).is_ok());
    let mut cursor = Cursor::new(vec);
    assert!(parse_openssh_header(&mut cursor).is_ok());
}