use base64::{decode,encode};
use ssh::errors::{SSHKeyParseError,SSHKeyRenderError};
use std::io::Cursor;
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Read;
use std::io::Write;

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

pub fn parse_openssh_header(input: &mut Cursor<Vec<u8>>) -> Result<(),SSHKeyParseError>
{
    let input_header = input.take(OPENSSH_MAGIC_HEADER.len()).bytes();
    if input_header.eq(OPENSSH_MAGIC_HEADER.as_bytes().iter()) {
        Ok(())
    } else {
        Err(SSHKeyParseError::NoOpenSSHMagicHeader)
    }
}

pub fn render_openssh_header<O: Write>(output: &mut O) -> Result<(),SSHKeyRenderError>
{
    Ok(output.write_all(OPENSSH_MAGIC_HEADER.as_bytes())?)
}

//------------------------------------------------------------------------------

pub fn parse_openssh_u32(input: &mut Cursor<Vec<u8>>) -> Result<u32,SSHKeyParseError>
{

}

//------------------------------------------------------------------------------

pub fn parse_openssh_string(input: &mut Cursor<Vec<u8>>) -> Result<(),SSHKeyParseError>
{
    panic!("string")
}

//------------------------------------------------------------------------------

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
    assert!(parse_openssh_header(&mut vec.iter()).is_ok());
}