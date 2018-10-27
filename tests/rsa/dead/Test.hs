import Codec.Crypto.RSA.Pure
import Control.Monad(forM_)
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Numeric

groupBy :: Int -> [a] -> [[a]]
groupBy _ [] = []
groupBy x xs =
  let (first, rest) = splitAt x xs
  in first : groupBy x rest

dictionary :: [String] -> Map String String
dictionary [] = Map.empty
dictionary (x:xs) =
  let rest = dictionary xs
      key  = take 1 x
      val  = drop 3 x
  in Map.insert key val rest

number :: String -> Integer
number x =
  case readHex x of
    [(v, _)] -> v
    _        -> error "number"

hash :: String -> (ByteString -> ByteString)
hash x =
  case x of
    "160" -> hashFunction hashSHA1
    "224" -> hashFunction hashSHA224
    "256" -> hashFunction hashSHA256
    "384" -> hashFunction hashSHA384
    "512" -> hashFunction hashSHA512

decrypter :: String ->
             (ByteString -> PrivateKey -> ByteString -> Either RSAError ByteString)
decrypter x = decryptOAEP hashfun (generateMGF1 hashfun)
  where hashfun = hash x

bytestring :: String -> ByteString
bytestring "" = BS.empty
bytestring xs =
  let (byte1, rest) = splitAt 2 xs
  in BS.cons (fromIntegral (number byte1)) (bytestring rest)

forceLookup :: String -> Map String String -> String
forceLookup x m =
  case Map.lookup x m of
    Just v  -> v
    Nothing -> error ("forceLookup: " ++ x)

runCase :: Map String String -> IO ()
runCase dict =
  do let d = number (forceLookup "d" dict)
         n = number (forceLookup "n" dict)
         m = bytestring (forceLookup "m" dict)
         s = bytestring (forceLookup "s" dict)
         c = bytestring (forceLookup "c" dict)
         public = PublicKey (512 `div` 8) n 65537
         private = PrivateKey public d 0 0 0 0 0
         decrypt = decrypter (forceLookup "h" dict)
     case decrypt BS.empty private m of
       Left err -> fail ("Error: " ++ show err)
       Right _  -> putStrLn "OK"

main :: IO ()
main =
  do strs <- lines `fmap` readFile "rsa512.test"
     let groups = groupBy 7 strs
     forM_ groups (runCase . dictionary)
