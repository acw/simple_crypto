{-# LANGUAGE PackageImports #-}
module DSA(dsaTasks)
 where

import Codec.Crypto.DSA.Pure
import Crypto.Hash(Digest, SHA256, hash)
import "cryptonite" Crypto.Random(SystemDRG,DRG(..),getRandomBytes,withDRG)
import "crypto-api" Crypto.Random(CryptoRandomGen(..), SystemRandom)
import Data.ByteArray(convert)
import qualified Data.ByteString as BS
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Math(showX,showBin)
import System.IO.Unsafe(unsafePerformIO)
import Task(Task(..),Test)
import Utils(HashAlg(..),generateHash,showHash)

import Debug.Trace

dsaSizes :: [(ParameterSizes, Int)]
dsaSizes = [(L1024_N160, 400),
            (L2048_N224, 100),
            (L2048_N256,  50),
            (L3072_N256,  25)]

dsaTasks :: [Task]
dsaTasks = concatMap generateTask dsaSizes

generateTask :: (ParameterSizes, Int) -> [Task]
generateTask (s, c) = [signTest s c]

signTest :: ParameterSizes -> Int -> Task
signTest sz cnt = Task {
    taskName = "DSA " ++ show sz ++ " signing",
    taskFile = "../testdata/dsa/sign" ++ show sz ++ ".test",
    taskTest = go,
    taskCount = cnt
  }
 where
  go :: Test
  go (memory, drg0) =
    case generateProbablePrimes sz (unsafePerformIO (newGenIO :: IO SystemRandom)) sha256 Nothing of
      Left _ -> trace "generate primes" $ goAdvance memory drg0
      Right (p, q, _, gen1) ->
        case generateUnverifiableGenerator p q of
          Nothing -> trace "generate g" $ goAdvance memory drg0
          Just g ->
            let params = Params p g q
            in case generateKeyPairWithParams params gen1 of
                 Left _ -> trace "generate key" $ goAdvance memory drg0
                 Right (pub, priv, gen1) ->
                   let (msg, drg1) = withDRG drg0 $ getRandomBytes =<< ((fromIntegral . BS.head) `fmap` getRandomBytes 1)
                       (hashf, drg2) = withDRG drg1 generateHash
                   in case signMessage' (translateHash hashf) kViaRFC6979 gen1 priv (BSL.fromStrict msg) of
                        Left _ ->
                          trace "sign failure" $ go (memory, drg2)
                        Right (sig, _) ->
                          let res = Map.fromList [("p", showX p),
                                                  ("q", showX q),
                                                  ("g", showX g),
                                                  ("y", showX (public_y pub)),
                                                  ("x", showX (private_x priv)),
                                                  ("m", showBin msg),
                                                  ("h", showHash hashf),
                                                  ("r", showX (sign_r sig)),
                                                  ("s", showX (sign_s sig))]
                          in (res, p, (memory, drg2))
  --
  goAdvance memory drg0 =
    let (bstr, drg1) = randomBytesGenerate 37 drg0
    in BS.null bstr `seq` go (memory, drg1)
  --
  translateHash Sha224 = Codec.Crypto.DSA.Pure.SHA224
  translateHash Sha256 = Codec.Crypto.DSA.Pure.SHA256
  translateHash Sha384 = Codec.Crypto.DSA.Pure.SHA384
  translateHash Sha512 = Codec.Crypto.DSA.Pure.SHA512

sha256 :: ByteString -> ByteString
sha256 = BSL.fromStrict . convert' . hash . BSL.toStrict
 where
  convert' :: Digest SHA256 -> BS.ByteString
  convert' = convert