{-# LANGUAGE ScopedTypeVariables #-}
import Control.Monad
import Codec.Crypto.DSA.Pure
import Control.Concurrent
import Crypto.Random.DRBG
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Char
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

keyIterations :: [ParameterSizes]
keyIterations = replicate 500 L1024_N160 ++
                replicate 500 L2048_N224 ++
                replicate 200 L2048_N256 ++
                replicate 100 L3072_N256

randomByteString :: CryptoRandomGen g => g -> (BS.ByteString, g)
randomByteString g =
  let Right (bs, g')   = genBytes 2 g
      [h,l]            = BS.unpack bs
      x                = (fromIntegral h `shiftL` 8) + (fromIntegral l)
      Right (res, g'') = genBytes (x `mod` 1024) g'
  in (res, g'')

randomHash :: CryptoRandomGen g => g -> ((HashFunction, String), g)
randomHash g =
  randomElement g [(SHA1,   "1"),
                   (SHA224, "224"),
                   (SHA256, "256"),
                   (SHA384, "384"),
                   (SHA512, "512")]

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

runSignatureGenerator :: Chan ParameterSizes ->
                         Chan [(String,String)] ->
                         IO ()
runSignatureGenerator inputs outputs =
  do rng0 :: GenBuffered SystemRandom <- newGenIO
     go Nothing rng0
 where
   go Nothing rng0 =
     do keySize <- readChan inputs
        go (Just keySize) rng0
   go (Just keySize) g0 =
     do let Right (public, private, _, g1) = generateKeyPair g0 keySize
        let (msg, g2) = randomByteString g1
        let msg' = BSL.fromStrict msg
        let ((hash, hashname), g3) = randomHash g2
        case signMessage' hash kViaRFC6979 g3 private msg' of
          Left _ ->
            go (Just keySize) g3
          Right (sig, g4) ->
            do unless (verifyMessage' hash public msg' sig) $
                 fail "DSA verification failed internally."
               let params = private_params private
               writeChan outputs [("p", showHex (params_p params) ""),
                                  ("g", showHex (params_g params) ""),
                                  ("q", showHex (params_q params) ""),
                                  ("x", showHex (private_x private) ""),
                                  ("y", showHex (public_y public) ""),
                                  ("h", hashname),
                                  ("m", showBinary msg),
                                  ("r", showHex (sign_r sig) ""),
                                  ("s", showHex (sign_s sig) "")]
               go Nothing g4

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
     sigthrs <- replicateM numThreads $
                  forkIO $ runSignatureGenerator sizeChan outputChan
     let bar = autoProgressBar (msg "Generating signature tests") percentage 60
     writeList2Chan sizeChan keyIterations
     g1 <- withFile "signature.test" WriteMode (writeData outputChan bar)
     return ()

randomElement :: CryptoRandomGen g => g -> [a] -> (a, g)
randomElement g xs =
  let Right (bs, g') = genBytes 1 g
      x              = BS.head bs
      idx            = fromIntegral x `mod` length xs
  in (xs !! idx, g')
