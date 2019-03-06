{-# LANGUAGE PackageImports #-}
module RSA(rsaTasks)
 where

import Crypto.Hash(SHA224(..),SHA256(..),SHA384(..),SHA512(..))
import "cryptonite" Crypto.Random
import Crypto.PubKey.MaskGenFunction(mgf1)
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15(sign)
import Crypto.PubKey.RSA.OAEP(OAEPParams(..),encrypt)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Char(chr,isPrint)
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Maybe(fromMaybe,isJust)
import Data.Word(Word8)
import Database(Database)
import Math(barrett,computeK,showX,showBin)
import Task(Task(..))
import Utils(HashAlg(..),generateHash,showHash)

rsaSizes :: [(Int, Int)]
rsaSizes = [(512,  400),
            (1024, 200),
            (2048, 100),
            (3072,  50),
            (4096,  50),
            (8192,  10),
            (15360, 5)]

rsaTasks :: [Task]
rsaTasks = concatMap generateTask rsaSizes

generateTask :: (Int, Int) -> [Task]
generateTask (s, c) = [signTest s c, encryptTest s c]

signTest :: Int -> Int -> Task
signTest sz cnt = Task {
    taskName = "RSA " ++ show sz ++ " signing",
    taskFile = "../testdata/rsa/sign" ++ show sz ++ ".test",
    taskTest = go,
    taskCount = cnt
  }
 where
  go db = withDRG' db go2
  --
  go2 :: MonadRandom m => m (Map String String, Integer)
  go2 = do (public, private) <- generate (sz `div` 8) 65537
           let d = private_d private
           let n = public_n public
           msg <- getRandomBytes =<< ((fromIntegral . BS.head) `fmap` getRandomBytes 1)
           hash <- generateHash
           case signWith hash private msg of
             Left _ -> go2
             Right sig -> return $ (Map.fromList [("d", showX d),
                                                  ("n", showX n),
                                                  ("k", showX (computeK n)),
                                                  ("u", showX (barrett n)),
                                                  ("h", showHash hash),
                                                  ("m", showBin msg),
                                                  ("s", showBin sig)], n)

withDRG' :: Database -> MonadPseudoRandom SystemDRG (Map String String, Integer) ->
            (Map String String, Integer, Database)
withDRG' (memory, drg) action =
  let ((res, n), drg') = withDRG drg action
  in (res, n, (memory, drg'))

signWith :: HashAlg -> PrivateKey -> BS.ByteString -> Either Error BS.ByteString
signWith Sha224 = sign Nothing (Just SHA224)
signWith Sha256 = sign Nothing (Just SHA256)
signWith Sha384 = sign Nothing (Just SHA384)
signWith Sha512 = sign Nothing (Just SHA512)

encryptTest :: Int -> Int -> Task
encryptTest sz cnt = Task {
    taskName = "RSA " ++ show sz ++ " encryption",
    taskFile = "../testdata/rsa/encrypt" ++ show sz ++ ".test",
    taskTest = go,
    taskCount = cnt
  }
 where
  go db = withDRG' db go2
  go2 = do (public, private) <- generate (sz `div` 8) 65537
           let d = private_d private
           let n = public_n public
           msg <- getRandomBytes =<< ((fromIntegral . BS.head) `fmap` getRandomBytes 1)
           hash <- generateHash
           label <- do len <- BS.head `fmap` getRandomBytes 1
                       if odd len
                         then return Nothing
                         else Just `fmap` genASCII (len `div` 2)
           let labelbstr = fromMaybe BS.empty (BSC.pack `fmap` label)
               labelAlive = if isJust label then 1 else (0 :: Integer)
           res <- encryptWith hash (BSC.pack `fmap` label) public msg
           case res of
             Left _ -> go2
             Right cipher ->
               return $ (Map.fromList [("d", showX d),
                                       ("n", showX n),
                                       ("k", showX (computeK n)),
                                       ("u", showX (barrett n)),
                                       ("h", showHash hash),
                                       ("m", showBin msg),
                                       ("l", showBin labelbstr),
                                       ("e", showX labelAlive),
                                       ("c", showBin cipher)], n)

genASCII :: MonadRandom m => Word8 -> m String
genASCII 0 = return ""
genASCII x =
  do v <- (BS.head `fmap` getRandomBytes 1)
     let c = chr (fromIntegral v)
     if (v < 128) && isPrint c
       then (c :) `fmap` genASCII (x - 1)
       else genASCII x

encryptWith :: MonadRandom m =>
               HashAlg -> Maybe BS.ByteString -> PublicKey -> BS.ByteString ->
               m (Either Error BS.ByteString)
encryptWith Sha224 mlabel = encrypt (OAEPParams SHA224 (mgf1 SHA224) mlabel)
encryptWith Sha256 mlabel = encrypt (OAEPParams SHA256 (mgf1 SHA256) mlabel)
encryptWith Sha384 mlabel = encrypt (OAEPParams SHA384 (mgf1 SHA384) mlabel)
encryptWith Sha512 mlabel = encrypt (OAEPParams SHA512 (mgf1 SHA512) mlabel)