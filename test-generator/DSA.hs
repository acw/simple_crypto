{-# LANGUAGE PackageImports #-}
module DSA(dsaTasks)
 where

import Codec.Crypto.DSA.Pure
import Crypto.Hash(Digest, SHA256, hash)
import "cryptonite" Crypto.Random(DRG(..),getRandomBytes,withDRG)
import Data.ByteArray(convert)
import qualified Data.ByteString as BS
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Math(showX,showBin)
import Task(Task(..),liftTest)
import Utils(HashAlg(..),generateHash,showHash)

dsaSizes :: [(ParameterSizes, Int)]
dsaSizes = [(L1024_N160, 400),
            (L2048_N224, 100),
            (L2048_N256,  50),
            (L3072_N256,  25)]

dsaTasks :: [Task]
dsaTasks = concatMap generateTask dsaSizes

generateTask :: (ParameterSizes, Int) -> [Task]
generateTask (s, c) = [signTest s c]

showParam :: ParameterSizes -> String
showParam L1024_N160 = "L1024N160"
showParam L2048_N224 = "L2048N224"
showParam L2048_N256 = "L2048N256"
showParam L3072_N256 = "L3072N256"

signTest :: ParameterSizes -> Int -> Task
signTest sz cnt = Task {
    taskName = "DSA " ++ show sz ++ " signing",
    taskFile = "../testdata/dsa/sign" ++ showParam sz ++ ".test",
    taskTest = liftTest go,
    taskCount = cnt
  }
 where
  go (memory, drg0) =
    case generateProbablePrimes sz drg0 sha256 Nothing of
      Left _ -> goAdvance memory drg0
      Right (p, q, _, drg1) ->
        case generateUnverifiableGenerator p q of
          Nothing -> goAdvance memory drg1
          Just g ->
            let params = Params p g q
            in case generateKeyPairWithParams params drg1 of
                 Left _ -> goAdvance memory drg1
                 Right (pub, priv, drg2) ->
                   let (msg, drg3) = withDRG drg2 $ getRandomBytes =<< ((fromIntegral . BS.head) `fmap` getRandomBytes 1)
                       (hashf, drg4) = withDRG drg3 generateHash
                   in case signMessage' (translateHash hashf) kViaRFC6979 drg4 priv (BSL.fromStrict msg) of
                        Left _ ->
                          go (memory, drg4)
                        Right (sig, drg5) ->
                          let res = Map.fromList [("p", showX p),
                                                  ("q", showX q),
                                                  ("g", showX g),
                                                  ("y", showX (public_y pub)),
                                                  ("x", showX (private_x priv)),
                                                  ("m", showBin msg),
                                                  ("h", showHash hashf),
                                                  ("r", showX (sign_r sig)),
                                                  ("s", showX (sign_s sig))]
                          in (res, p, (memory, drg5))
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