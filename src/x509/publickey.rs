use cryptonum::unsigned::{U3072,U2048,U1024,U256,U192};
use dsa::{DSAPublic,DSAPublicKey,DSAParameters};
use dsa::{L3072N256,L2048N256,L2048N224,L1024N160};
use ecdsa::{ECDSAEncodeErr,ECDSAPublic,ECCPublicKey};
use ecdsa::curve::{P192,P224,P256,P384,P521};
use num::BigUint;
use rsa::RSAPublic;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,OID,ToASN1,
                  der_decode,der_encode,from_der};
use utils::TranslateNums;
use x509::error::X509ParseError;

pub enum X509PublicKey {
    DSA(DSAPublic),
    RSA(RSAPublic),
    ECDSA(ECDSAPublic)
}

impl From<X509PublicKey> for Option<DSAPublic> {
    fn from(x: X509PublicKey) -> Option<DSAPublic> {
        match x {
            X509PublicKey::DSA(x) => Some(x),
            _                     => None
        }
    }
}

impl From<X509PublicKey> for Option<RSAPublic> {
    fn from(x: X509PublicKey) -> Option<RSAPublic> {
        match x {
            X509PublicKey::RSA(x) => Some(x),
            _                     => None
        }
    }
}

impl From<X509PublicKey> for Option<ECDSAPublic> {
    fn from(x: X509PublicKey) -> Option<ECDSAPublic> {
        match x {
            X509PublicKey::ECDSA(x) => Some(x),
            _                       => None
        }
    }
}

pub enum X509EncodeErr {
    ASN1EncodeErr(ASN1EncodeErr),
    ECDSAEncodeErr(ECDSAEncodeErr)
}

impl From<ASN1EncodeErr> for X509EncodeErr {
    fn from(x: ASN1EncodeErr) -> X509EncodeErr {
        X509EncodeErr::ASN1EncodeErr(x)
    }
}

impl From<ECDSAEncodeErr> for X509EncodeErr {
    fn from(x: ECDSAEncodeErr) -> X509EncodeErr {
        X509EncodeErr::ECDSAEncodeErr(x)
    }
}

impl ToASN1 for X509PublicKey {
    type Error = X509EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class) -> Result<Vec<ASN1Block>,X509EncodeErr> {
        let block = match self {
            X509PublicKey::RSA(x)   => encode_rsa_key(c, x)?,
            X509PublicKey::DSA(x)   => encode_dsa_key(c, x)?,
            X509PublicKey::ECDSA(x) => encode_ecdsa_key(c, x)?,
        };
        Ok(vec![block])
    }
}

impl FromASN1 for X509PublicKey {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(X509PublicKey, &[ASN1Block]), Self::Error>
    {
        let (block, rest) = v.split_first().ok_or(X509ParseError::NotEnoughData)?;

        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //      algorithm            AlgorithmIdentifier,
        //      subjectPublicKey     BIT STRING  }
        if let &ASN1Block::Sequence(_, _, ref info) = block {
            let (id, malginfo) = strip_algident(&info[0])?;

            if id == oid!(1,2,840,113549,1,1,1) {
                let key = decode_rsa_key(&info[1])?;
                return Ok((X509PublicKey::RSA(key), rest));
            }

            if id == oid!(1,2,840,10040,4,1) {
                if let Some(alginfo) = malginfo {
                    let key = decode_dsa_key(alginfo, &info[1])?;
                    return Ok((X509PublicKey::DSA(key), rest));
                } 
            }

            if id == oid!(1,2,840,10045,2,1) {
                if let Some(alginfo) = malginfo {
                    let key = decode_ecdsa_key(alginfo, &info[1..])?;
                    return Ok((X509PublicKey::ECDSA(key), rest));
                } 
            }
        }

        Err(X509ParseError::IllFormedKey)
    }
}

//------------------------------------------------------------------------------
//
// RSA Public Key encoding / decoding
//
//------------------------------------------------------------------------------

fn encode_rsa_key(c: ASN1Class, x: &RSAPublic) -> Result<ASN1Block,ASN1EncodeErr>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,113549,1,1,1));
    let bstr = der_encode(x)?;
    let objkey = ASN1Block::BitString(c, 0, bstr.len() * 8, bstr);
    Ok(ASN1Block::Sequence(c, 0, vec![objoid, objkey]))
}

fn decode_rsa_key(x: &ASN1Block) -> Result<RSAPublic,X509ParseError>
{
    if let &ASN1Block::BitString(_, _, _, ref bstr) = x {
        der_decode(bstr).map_err(|x| X509ParseError::RSAError(x))
    } else {
        Err(X509ParseError::NotEnoughData)
    }
}

//------------------------------------------------------------------------------
//
// DSA Public Key encoding / decoding
//
//------------------------------------------------------------------------------

fn encode_dsa_key(c: ASN1Class, x: &DSAPublic) -> Result<ASN1Block,ASN1EncodeErr>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10040,4,1));
    let (mut objparams, bstr) = match x {
        DSAPublic::DSAPublicL1024N160(x) => (x.params.to_asn1_class(c)?, der_encode(x)?),
        DSAPublic::DSAPublicL2048N224(x) => (x.params.to_asn1_class(c)?, der_encode(x)?),
        DSAPublic::DSAPublicL2048N256(x) => (x.params.to_asn1_class(c)?, der_encode(x)?),
        DSAPublic::DSAPublicL3072N256(x) => (x.params.to_asn1_class(c)?, der_encode(x)?)
    };
    objparams.insert(0, objoid);
    let headinfo = ASN1Block::Sequence(c, 0, objparams);
    let objkey = ASN1Block::BitString(c, 0, bstr.len() * 8, bstr);
    Ok(ASN1Block::Sequence(c, 0, vec![headinfo, objkey]))
}

fn decode_dsa_key(info: ASN1Block, key: &ASN1Block) -> Result<DSAPublic,X509ParseError>
{
    if let ASN1Block::Sequence(_, _, pqg) = info {
        if pqg.len() != 3 { return Err(X509ParseError::InvalidDSAInfo); }

        let puint = decode_biguint(&pqg[0])?;
        let guint = decode_biguint(&pqg[1])?;
        let quint = decode_biguint(&pqg[2])?;

        if puint.bits() > 2048 {
            let p = U3072::from_num(&puint).ok_or(X509ParseError::InvalidDSAInfo)?;
            let q = U3072::from_num(&quint).ok_or(X509ParseError::InvalidDSAInfo)?;
            let g = U256::from_num(&guint).ok_or(X509ParseError::InvalidDSAInfo)?;
            let params = L3072N256::new(p, q, g);

            if let ASN1Block::BitString(_, _, _, ybstr) = key {
                let blocks = from_der(ybstr)?;
                let (iblk,_) = blocks.split_first().ok_or(X509ParseError::InvalidDSAKey)?;
                if let ASN1Block::Integer(_,_,ynum) = iblk {
                    let y = U3072::from_num(ynum).ok_or(X509ParseError::InvalidDSAKey)?;
                    let key = DSAPublicKey::<L3072N256>::new(params, y);
                    let reskey = DSAPublic::DSAPublicL3072N256(key);
                    return Ok(reskey);
                }
            } 
            
            return Err(X509ParseError::InvalidDSAKey)
        }

        if puint.bits() > 1024 {
            if guint.bits() > 224 {
                let p = U2048::from_num(&puint).ok_or(X509ParseError::InvalidDSAInfo)?;
                let q = U2048::from_num(&quint).ok_or(X509ParseError::InvalidDSAInfo)?;
                let g = U256::from_num(&guint).ok_or(X509ParseError::InvalidDSAInfo)?;
                let params = L2048N256::new(p, q, g);

                if let ASN1Block::BitString(_, _, _, ybstr) = key {
                    let blocks = from_der(ybstr)?;
                    let (iblk,_) = blocks.split_first().ok_or(X509ParseError::InvalidDSAKey)?;
                    if let ASN1Block::Integer(_,_,ynum) = iblk {
                        let y = U2048::from_num(ynum).ok_or(X509ParseError::InvalidDSAKey)?;
                        let key = DSAPublicKey::<L2048N256>::new(params, y);
                        let reskey = DSAPublic::DSAPublicL2048N256(key);
                        return Ok(reskey);
                    }
                }

                return Err(X509ParseError::InvalidDSAKey)
            } else {
                let p = U2048::from_num(&puint).ok_or(X509ParseError::InvalidDSAInfo)?;
                let q = U2048::from_num(&quint).ok_or(X509ParseError::InvalidDSAInfo)?;
                let g = U256::from_num(&guint).ok_or(X509ParseError::InvalidDSAInfo)?;
                let params = L2048N224::new(p, q, g);

                if let ASN1Block::BitString(_, _, _, ybstr) = key {
                    let blocks = from_der(ybstr)?;
                    let (iblk,_) = blocks.split_first().ok_or(X509ParseError::InvalidDSAKey)?;
                    if let ASN1Block::Integer(_,_,ynum) = iblk {
                        let y = U2048::from_num(ynum).ok_or(X509ParseError::InvalidDSAKey)?;
                        let key = DSAPublicKey::<L2048N224>::new(params, y);
                        let reskey = DSAPublic::DSAPublicL2048N224(key);
                        return Ok(reskey);
                    }
                } 

                return Err(X509ParseError::InvalidDSAKey)
            }
        }

        let p = U1024::from_num(&puint).ok_or(X509ParseError::InvalidDSAInfo)?;
        let q = U1024::from_num(&quint).ok_or(X509ParseError::InvalidDSAInfo)?;
        let g = U192::from_num(&guint).ok_or(X509ParseError::InvalidDSAInfo)?;
        let params = L1024N160::new(p, q, g);

        if let ASN1Block::BitString(_, _, _, ybstr) = key {
            let blocks = from_der(ybstr)?;
            let (iblk,_) = blocks.split_first().ok_or(X509ParseError::InvalidDSAKey)?;
            if let ASN1Block::Integer(_,_,ynum) = iblk {
                let y = U1024::from_num(ynum).ok_or(X509ParseError::InvalidDSAKey)?;
                let key = DSAPublicKey::<L1024N160>::new(params, y);
                let reskey = DSAPublic::DSAPublicL1024N160(key);
                return Ok(reskey);
            }
        } 
        
        return Err(X509ParseError::InvalidDSAKey)
    }

    Err(X509ParseError::InvalidDSAInfo)
}

//------------------------------------------------------------------------------
//
// ECDSA Public Key encoding
//
//------------------------------------------------------------------------------

fn encode_ecdsa_key(c: ASN1Class, x: &ECDSAPublic) -> Result<ASN1Block,ECDSAEncodeErr>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10045,2,1));
    let (base_curve_oid, mut keyvec) = match x {
        ECDSAPublic::P192(k) => (oid!(1,2,840,10045,3,1,1), k.to_asn1_class(c)?),
        ECDSAPublic::P224(k) => (oid!(1,3,132,0,33), k.to_asn1_class(c)?),
        ECDSAPublic::P256(k) => (oid!(1,2,840,10045,3,1,7), k.to_asn1_class(c)?),
        ECDSAPublic::P384(k) => (oid!(1,3,132,0,34), k.to_asn1_class(c)?),
        ECDSAPublic::P521(k) => (oid!(1,3,132,0,35), k.to_asn1_class(c)?),
    };
    let curve_oid = ASN1Block::ObjectIdentifier(c, 0, base_curve_oid);
    let header = ASN1Block::Sequence(c, 0, vec![objoid, curve_oid]);
    keyvec.insert(0, header);
    Ok(ASN1Block::Sequence(c, 0, keyvec))
}

fn decode_ecdsa_key(info: ASN1Block, keybls: &[ASN1Block]) -> Result<ECDSAPublic,X509ParseError>
{
    if let ASN1Block::ObjectIdentifier(_, _, oid) = info {
        if oid == oid!(1,2,840,10045,3,1,1) {
            let (res, _) = ECCPublicKey::<P192>::from_asn1(keybls)?;
            return Ok(ECDSAPublic::P192(res));
        }

        if oid == oid!(1,3,132,0,33) {
            let (res, _) = ECCPublicKey::<P224>::from_asn1(keybls)?;
            return Ok(ECDSAPublic::P224(res));
        }

        if oid == oid!(1,2,840,10045,3,1,7) {
            let (res, _) = ECCPublicKey::<P256>::from_asn1(keybls)?;
            return Ok(ECDSAPublic::P256(res));
        }

        if oid == oid!(1,3,132,0,34) {
            let (res, _) = ECCPublicKey::<P384>::from_asn1(keybls)?;
            return Ok(ECDSAPublic::P384(res));
        }

        if oid == oid!(1,3,132,0,35) {
            let (res, _) = ECCPublicKey::<P521>::from_asn1(keybls)?;
            return Ok(ECDSAPublic::P521(res));
        }
    }

    Err(X509ParseError::UnknownEllipticCurve)
}

fn strip_algident(block: &ASN1Block)
    -> Result<(OID, Option<ASN1Block>),X509ParseError>
{
    match block {
        &ASN1Block::ObjectIdentifier(_, _, ref oid) => {
            Ok((oid.clone(), None))
        }
        &ASN1Block::Sequence(_, _, ref items) => {
            let (oid, _) = strip_algident(&items[0])?;
            Ok((oid, Some(items[1].clone())))
        }
        _ => Err(X509ParseError::IllFormedAlgoInfo)
    }
}

fn decode_biguint(b: &ASN1Block) -> Result<BigUint,X509ParseError> {
    match b {
        &ASN1Block::Integer(_, _, ref v) => {
            match v.to_biguint() {
                Some(sn) => Ok(sn),
                _        => Err(X509ParseError::InvalidDSAInfo)
            }
        }
        _ =>
            Err(X509ParseError::InvalidDSAInfo)
    }
}