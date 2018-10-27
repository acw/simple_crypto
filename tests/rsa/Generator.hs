import Codec.Crypto.RSA.Pure
import Control.Monad(forM_)
import Crypto.Random
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Numeric
import System.IO

force :: Show a => Either a b -> b
force (Left  e) = error ("Force failure: " ++ show e)
force (Right x) = x

forceGen :: CryptoRandomGen g => g -> Int -> (BSL.ByteString, g)
forceGen g x = 
  let (bs, g') = force (genBytes x g)
  in (BSL.fromStrict bs, g')

message :: CryptoRandomGen g => g -> (BSL.ByteString, g)
message g =
  let (lenbs, g') = forceGen g 2
      [len0,len1] = BSL.unpack lenbs
      len         = (fromIntegral len1 * 2) + fromIntegral len0
  in forceGen g' len

keyPair :: CryptoRandomGen g => g -> Int -> (PublicKey, PrivateKey, g)
keyPair g size = force (generateKeyPair g size)

hash :: CryptoRandomGen g => g -> (HashInfo, g)
hash g =
  let (hbs, g') = forceGen g 1
      [hb]      = BSL.unpack hbs
  in case hb `mod` 5 of
       0 -> (hashSHA1,   g')
       1 -> (hashSHA224, g')
       2 -> (hashSHA256, g')
       3 -> (hashSHA384, g')
       4 -> (hashSHA512, g')
       _ -> error "World broken"

showBytes :: BSL.ByteString -> String
showBytes bs = go (BSL.unpack bs)
 where
  go [] = ""
  go (x:rest)
   | x < 0x10  = "0" ++ showHex x "" ++ go rest
   | otherwise = showHex x "" ++ go rest

genCase :: CryptoRandomGen g => g -> Int -> (Map String String, g)
genCase g0 size =
  let (pub, priv, g1) = keyPair g0 size
      (msg, g2)       = message g1
      (hashi, g3)     = hash g2
      hashfun         = hashFunction hashi
      hashlen         = 8 * BSL.length (hashfun BSL.empty)
      n               = public_n pub
      d               = private_d priv
      esig            = rsassa_pkcs1_v1_5_sign hashi priv msg
      ecipher         = encryptOAEP g3 hashfun (generateMGF1 hashfun)
                                    BSL.empty pub msg
  in case (esig, ecipher) of
       (Right sig, Right (cipher, g4)) ->
         (Map.fromList [("d", Numeric.showHex d ""),
                        ("n", Numeric.showHex n ""),
                        ("h", show hashlen),
                        ("m", showBytes msg),
                        ("s", showBytes sig),
                        ("c", showBytes cipher)], g4)
       (Left _, Right (_, g4)) ->
         genCase g4 size
       (_, _) ->
         genCase g3 size

go :: CryptoRandomGen g => g -> Handle -> Int -> Int -> IO ()
go _ _ _ 0 = return ()
go g hndl size count =
  do let (map, g') = genCase g size
     forM_ (Map.toList map) $ \ (key, val) ->
       do hPutStr   hndl key
          hPutStr   hndl ": "
          hPutStrLn hndl val
     putStr "."
     hFlush stdout
     go g' hndl size (count - 1)

main :: IO ()
main =
  forM_ [512,1024,2048,3072,4096,8192,15360] $ \ size ->
    withFile ("rsa" ++ show size ++ ".test") WriteMode $ \ hndl ->
      do gen <- newGenIO :: IO SystemRandom
         putStr ("Generating " ++ show size ++ "-bit test cases ")
         go gen hndl size 750
         putStrLn " done."

