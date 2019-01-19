module RFC6979
--       (
--         rfcTasks
--       )
 where

import Crypto.Hash(SHA224(..),SHA256(..),SHA384(..),SHA512(..))
import Crypto.MAC.HMAC(HMAC,hmac)
import Crypto.Number.Generate(generateBetween)
import Crypto.Random(getRandomBytes,withDRG)
import Data.Bits(shiftL,shiftR,(.&.))
import qualified Data.ByteArray as B
import qualified Data.ByteString as S
import Data.Char(toUpper)
import qualified Data.Map.Strict as Map
import Math(showBin,showX)
import Task(Task(..))
import Utils(HashAlg(..), runHash)


runHMAC :: HashAlg -> S.ByteString -> S.ByteString -> S.ByteString
runHMAC Sha224 key msg = S.pack (B.unpack (hmac key msg :: HMAC SHA224))
runHMAC Sha256 key msg = S.pack (B.unpack (hmac key msg :: HMAC SHA256))
runHMAC Sha384 key msg = S.pack (B.unpack (hmac key msg :: HMAC SHA384))
runHMAC Sha512 key msg = S.pack (B.unpack (hmac key msg :: HMAC SHA512))

generateKStream :: HashAlg -> S.ByteString -> Integer -> Integer -> Int -> [Integer]
generateKStream alg m x q qlen = nextK bigK2 bigV2
 where
  h1 = runHash alg m
  bigV0 = S.replicate (S.length h1) 0x01
  bigK0 = S.replicate (S.length h1) 0x00
  seed1 = S.concat [bigV0, S.singleton 0x00, int2octets qlen x, bits2octets qlen q h1]
  bigK1 = runHMAC alg bigK0 seed1
  bigV1 = runHMAC alg bigK1 bigV0
  seed2 = S.concat [bigV1, S.singleton 0x01, int2octets qlen x, bits2octets qlen q h1]
  bigK2 = runHMAC alg bigK1 seed2
  bigV2 = runHMAC alg bigK2 bigV1
  --
  nextK bigK bigV =
    let (bigV', bigT) = buildT bigK bigV S.empty
        k             = bits2int qlen bigT
        bigK'         = runHMAC alg bigK (bigV' `S.append` S.singleton 0)
        bigV''        = runHMAC alg bigK' bigV'
    in if k < q then (k : nextK bigK' bigV'') else nextK bigK' bigV''
  buildT bigK bigV bigT
    | S.length bigT * 8 >= qlen = (bigV, bigT)
    | otherwise =
        let bigV' = runHMAC alg bigK bigV
        in buildT bigK bigV' (bigT `S.append` bigV')

bits2int :: Int -> S.ByteString -> Integer
bits2int qlen bstr = reduce (go bstr 0)
 where
  reduce x =
    let vlen = S.length bstr * 8
    in if vlen > qlen
         then x `shiftR` (vlen - qlen)
         else x
  --
  go x acc =
    case S.uncons x of
      Nothing -> acc
      Just (v, rest) ->
        go rest ((acc `shiftL` 8) + fromIntegral v)

int2octets ::  Int -> Integer -> S.ByteString
int2octets lenBits x =
  S.pack (pad (rlen `div` 8) (reverse (go x)))
 where
  rlen = 8 * ((lenBits + 7) `div` 8)
  pad target ls 
    | length ls > target = drop (length ls - target) ls
    | length ls < target = pad target (0 : ls)
    | otherwise          = ls
  --
  go 0 = []
  go v = (fromIntegral (v .&. 0xFF)) : go (v `shiftR` 8)

bits2octets :: Int -> Integer -> S.ByteString -> S.ByteString
bits2octets qlen q bstr =
  let z1 = bits2int qlen bstr
      z2 = if z1 > q then z1 - q else z1
  in int2octets qlen z2

rfc6979Test :: HashAlg -> Task
rfc6979Test alg = Task {
    taskName = name ++ " RFC 6979 deterministic k-generation",
    taskFile = "../testdata/rfc6979/" ++ name ++ ".test",
    taskTest = go,
    taskCount = 1000
}
 where
  name = map toUpper (show alg)
  go (memory0, drg0) =
    let (qlen, drg1) = withDRG drg0 $ generateBetween 160 521
        (key, drg2) = withDRG drg1 $ generateBetween 1 ((2 ^ qlen) - 1)
        (q, drg3) = withDRG drg2 $ generateBetween 1 ((2 ^ qlen) - 1)
        (dataSize, drg4) = withDRG drg3 $ generateBetween 1 1024
        (msg, drg5) = withDRG drg4 $ getRandomBytes (fromIntegral dataSize)
        h1 = runHash alg msg
        ks = generateKStream alg msg key q (fromIntegral qlen)
        res = Map.fromList [("q", showX q), ("l", showX qlen),
                            ("x", showX key), ("h", showBin h1),
                            ("k", showX (ks !! 0)),
                            ("y", showX (ks !! 1)),
                            ("z", showX (ks !! 2))]
    in (res, qlen, (memory0, drg5))

rfcTasks :: [Task]
rfcTasks = [rfc6979Test Sha224, rfc6979Test Sha256,
            rfc6979Test Sha384, rfc6979Test Sha512]