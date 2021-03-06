{-# LANGUAGE PackageImports #-}
module Database(
         Database,
         emptyDatabase,
         generateNum, genSign
       )
 where

import "crypto-api" Crypto.Random(CryptoRandomGen(..),SystemRandom)
import "cryptonite" Crypto.Random(DRG(..))
import              Data.ByteArray(convert)
import              Data.Bits(shiftL,testBit)
import qualified    Data.ByteString as S
import              Data.Map.Strict(Map)
import qualified    Data.Map.Strict as Map

type Database = (Map String [Integer], SystemRandom)

instance DRG SystemRandom where
   randomBytesGenerate x g =
     case genBytes x g of
       Left e -> error ("Data generation error: " ++ show e)
       Right (res, g') -> (convert res, g')

emptyDatabase :: SystemRandom -> Database
emptyDatabase g0 = (Map.empty, g0)

generateNum :: Database -> String -> Int -> (Integer, Database)
generateNum (db, rng0) varname size =
  let (x, rng1) = randomBytesGenerate (size `div` 8) rng0
      x'        = integerize x
      before    = Map.findWithDefault [] varname db
  in if length (filter (== x') before) < 10
       then (x', (Map.insert varname (x':before) db, rng1))
       else generateNum (db, rng1) varname size

genSign :: (Integer, Database) -> (Integer, Database)
genSign (x, (db, rng0)) =
  let (n, rng1) = randomBytesGenerate 1 rng0
      n' = integerize n 
  in if testBit n' 0 then (0 - x, (db, rng1)) else (x, (db, rng1))

integerize :: S.ByteString -> Integer
integerize = go 0
 where
  go acc bstr =
    case S.uncons bstr of
      Nothing -> acc
      Just (v,rest) ->
        go ((acc `shiftL` 8) + fromIntegral v) rest