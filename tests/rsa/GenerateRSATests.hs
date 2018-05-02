{-# LANGUAGE ScopedTypeVariables #-}
import Control.Monad
import Codec.Crypto.RSA.Pure
import Control.Concurrent
import Crypto.Random.DRBG
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.List
import qualified Data.Map.Strict as Map
import GHC.Integer.GMP.Internals
import Numeric
import System.IO
import System.ProgressBar
import System.Random
import Debug.Trace

numThreads :: Int
numThreads = 4

keySizes :: [Int]
keySizes = [512,1024,2048,3072,4096,7680,8192,15360]

keyIterations :: [Int]
keyIterations = replicate 500 512   ++
                replicate 500 1024  ++
                replicate 250 2048  ++
                replicate 125 3072  ++
                replicate 50  4096  ++
                replicate 5   7680  ++
                replicate 2   8192  ++
                replicate 1   15360

randomByteString :: CryptoRandomGen g => g -> (BS.ByteString, g)
randomByteString g =
  let Right (bs, g')   = genBytes 2 g
      [h,l]            = BS.unpack bs
      x                = (fromIntegral h `shiftL` 8) + (fromIntegral l)
      Right (res, g'') = genBytes (x `mod` 1024) g'
  in (res, g'')

randomHash :: CryptoRandomGen g => g -> ((HashInfo, String), g)
randomHash g =
  randomElement g [(hashSHA1,   "1"),
                   (hashSHA224, "224"),
                   (hashSHA256, "256"),
                   (hashSHA384, "384"),
                   (hashSHA512, "512")]

showBinary :: BS.ByteString -> String
showBinary v = go v
 where
  go bstr =
    case BS.uncons bstr of
      Nothing ->
        ""
      Just (x, rest) ->
        let high = showHex (x `shiftR` 4) ""
            low  = showHex (x .&. 0xF)    ""
        in high ++ low ++ go rest

dump :: Handle -> [(String,String)] -> IO ()
dump hndl = mapM_ writeItem
 where
  writeItem (name, value) =
    do hPutStr   hndl name
       hPutStr   hndl ": "
       hPutStrLn hndl value

mkProgress x y = Progress (fromIntegral x) (fromIntegral y)

runSignatureGenerator :: Chan Int -> Chan [(String,String)] -> IO ()
runSignatureGenerator inputs outputs =
  do rng0 :: GenBuffered SystemRandom <- newGenIO
     go Nothing rng0
 where
   go Nothing rng0 =
     do keySize <- readChan inputs
        go (Just keySize) rng0
   go (Just keySize) g0 =
     do unless (keySize `elem` keySizes) $
           fail ("Bad key size: " ++ show keySize)
        let Right (public, private, g1) = generateKeyPair g0 keySize
        unless (private_d private `shiftR` keySize == 0) $
           fail ("Bad private key size.")
        unless (public_n public `shiftR` keySize == 0) $
           fail ("Bad private key size.")
        let (message, g2) = randomByteString g1
        let ((hash, hashname), g3) = randomHash g2
        case rsassa_pkcs1_v1_5_sign hash private (BSL.fromStrict message) of
          Left _ ->
            go (Just keySize) g3
          Right sig ->
            case rsassa_pkcs1_v1_5_verify hash public (BSL.fromStrict message) sig of
              Left err ->
                fail ("RSA Verification error: " ++ show err)
              Right False ->
                fail ("RSA verification failed?!")
              Right True ->
                do writeChan outputs [("d", showHex (private_d private) ""),
                                      ("n", showHex (public_n public) ""),
                                      ("h", hashname),
                                      ("k", showHex keySize ""),
                                      ("l", showHex (BS.length message) ""),
                                      ("m", showBinary message),
                                      ("s", showBinary (BSL.toStrict sig))]
                   go Nothing g3

writeData :: Chan [(String,String)] -> (Progress -> IO ()) -> Handle -> IO ()
writeData outputChan progressBar hndl = go 0
 where
  count = fromIntegral (length keyIterations)
  go x | x == count = return ()
       | otherwise = do output <- readChan outputChan
                        dump hndl output
                        hFlush hndl
                        progressBar (Progress (x + 1) count)
                        go (x + 1)

main :: IO ()
main =
  do sizeChan <- newChan
     outputChan <- newChan
     --
     replicateM_ numThreads $
        void $ forkIO $ runSignatureGenerator sizeChan outputChan
     --
     unless (all (`elem` keySizes) keyIterations) $
        fail "System setup failure."
     writeList2Chan sizeChan keyIterations
     --
     let bar = autoProgressBar (msg "Generating test material") percentage 60
     g1 <- withFile "signature.test" WriteMode (writeData outputChan bar)
     return ()

randomElement :: CryptoRandomGen g => g -> [a] -> (a, g)
randomElement g xs =
  let Right (bs, g') = genBytes 1 g
      x              = BS.head bs
      idx            = fromIntegral x `mod` length xs
  in (xs !! idx, g')
