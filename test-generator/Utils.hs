module Utils(HashAlg(..), generateHash, runHash, showHash)
 where

import Crypto.Hash(Digest,SHA224(..),SHA256(..),SHA384(..),SHA512(..),hash)
import Crypto.Number.Generate(generateBetween)
import Crypto.Random(MonadRandom)
import qualified Data.ByteArray as B
import qualified Data.ByteString as S
import Math(showX)

data HashAlg = Sha224 | Sha256 | Sha384 | Sha512
 deriving (Eq, Show)

runHash :: HashAlg -> S.ByteString -> S.ByteString
runHash Sha224 x = S.pack (B.unpack (hash x :: Digest SHA224))
runHash Sha256 x = S.pack (B.unpack (hash x :: Digest SHA256))
runHash Sha384 x = S.pack (B.unpack (hash x :: Digest SHA384))
runHash Sha512 x = S.pack (B.unpack (hash x :: Digest SHA512))

showHash :: HashAlg -> String
showHash Sha224 = showX (224 :: Int)
showHash Sha256 = showX (256 :: Int)
showHash Sha384 = showX (384 :: Int)
showHash Sha512 = showX (512 :: Int)

generateHash :: MonadRandom m => m HashAlg
generateHash =
    do x <- generateBetween 0 3
       case x of
         0 -> return Sha224
         1 -> return Sha256
         2 -> return Sha384
         3 -> return Sha512
         _ -> fail "Incompatible random number"
