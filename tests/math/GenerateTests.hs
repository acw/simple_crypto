import Control.Monad
import Data.Bits(shiftL,(.&.))
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import GHC.Integer.GMP.Internals(powModInteger)
import Numeric(showHex)
import Prelude hiding (log)
import System.Environment(getArgs)
import System.IO(hFlush,stdout,IOMode(..),withFile,Handle,hClose,hPutStrLn)
import System.Random(StdGen,newStdGen,random)

testTypes :: [(String, Int -> StdGen -> (Map String String, StdGen))]
testTypes = [("addition", addTest),
             ("modadd", modaddTest),
             ("subtraction", subTest),
             ("multiplication", mulTest),
             ("expandingmul", expmulTest),
             ("modmul", modmulTest),
             ("squaring", squareTest),
             ("modsq", modsqTest),
             ("modexp", modexpTest),
             ("bmodexp", bmodexpTest),
             ("division", divTest),
             ("barrett_gen", barrettGenTest),
             ("barrett_reduce", barrettReduceTest)
            ]

bitSizes :: [Int]
bitSizes = [192,256,384,512,576,1024,2048,3072,4096,8192,15360]

numTests :: Int
numTests = 1000

mask :: Int -> Integer
mask bitsize = (1 `shiftL` bitsize) - 1

splitMod :: Int -> [Integer] -> [Integer]
splitMod bitsize xs = filtered ++ [m]
 where
  xs'      = map (\x -> x .&. mask bitsize) xs
  m        = maximum xs'
  filtered = go xs'
  go (x:xs) | x == m    = xs
            | otherwise = x : go xs

addTest :: Int -> StdGen -> (Map String String, StdGen)
addTest bitsize gen0 = (res, gen2)
 where
  (a, gen1) = random gen0
  (b, gen2) = random gen1
  a'        = a .&. mask bitsize
  b'        = b .&. mask bitsize
  c         = (a' + b') .&. mask bitsize
  res       = Map.fromList [("a", showHex a' ""),
                            ("b", showHex b' ""),
                            ("c", showHex c  "")]

modaddTest :: Int -> StdGen -> (Map String String, StdGen)
modaddTest bitsize gen0 = (res, gen2)
 where
  (a, gen1)  = random gen0
  (b, gen2)  = random gen1
  (m, gen3)  = random gen2
  [a',b',m'] = splitMod bitsize [a,b,m]
  c          = (a' + b') `mod` m'
  res        = Map.fromList [("a", showHex a' ""),
                             ("b", showHex b' ""),
                             ("m", showHex m' ""),
                             ("c", showHex c  "")]

subTest :: Int -> StdGen -> (Map String String, StdGen)
subTest bitsize gen0 = (res, gen2)
 where
  (a, gen1) = random gen0
  (b, gen2) = random gen1
  a'        = a .&. mask bitsize
  b'        = b .&. mask bitsize
  c         = (a' - b') .&. mask bitsize
  res       = Map.fromList [("a", showHex a' ""),
                            ("b", showHex b' ""),
                            ("c", showHex c  "")]

mulTest :: Int -> StdGen -> (Map String String, StdGen)
mulTest bitsize gen0 = (res, gen2)
 where
  (a, gen1) = random gen0
  (b, gen2) = random gen1
  a'        = a .&. mask bitsize
  b'        = b .&. mask bitsize
  c         = (a' * b') .&. mask bitsize
  res       = Map.fromList [("a", showHex a' ""),
                            ("b", showHex b' ""),
                            ("c", showHex c  "")]

expmulTest :: Int -> StdGen -> (Map String String, StdGen)
expmulTest bitsize gen0 = (res, gen2)
 where
  (a, gen1) = random gen0
  (b, gen2) = random gen1
  a'        = a .&. mask bitsize
  b'        = b .&. mask bitsize
  c         = (a' * b')
  res       = Map.fromList [("a", showHex a' ""),
                            ("b", showHex b' ""),
                            ("c", showHex c  "")]

modmulTest :: Int -> StdGen -> (Map String String, StdGen)
modmulTest bitsize gen0 = (res, gen2)
 where
  (a, gen1)  = random gen0
  (b, gen2)  = random gen1
  (m, gen3)  = random gen2
  [a',b',m'] = splitMod bitsize [a,b,m]
  c          = (a' * b') `mod` m'
  res        = Map.fromList [("a", showHex a' ""),
                             ("b", showHex b' ""),
                             ("m", showHex m' ""),
                             ("c", showHex c  "")]

squareTest :: Int -> StdGen -> (Map String String, StdGen)
squareTest bitsize gen0 = (res, gen1)
 where
  (a, gen1) = random gen0
  a'        = a .&. mask bitsize
  r         = a' * a'
  res       = Map.fromList [("a", showHex a' ""),
                            ("r", showHex r  "")]

modsqTest :: Int -> StdGen -> (Map String String, StdGen)
modsqTest bitsize gen0 = (res, gen1)
 where
  (a, gen1) = random gen0
  (m, gen3) = random gen1
  [a',m']   = splitMod bitsize [a,m]
  r         = (a' * a') `mod` m'
  res       = Map.fromList [("a", showHex a' ""),
                            ("m", showHex m' ""),
                            ("r", showHex r  "")]

modexpTest :: Int -> StdGen -> (Map String String, StdGen)
modexpTest bitsize gen0 = (res, gen2)
 where
  (b, gen1)  = random gen0
  (e, gen2)  = random gen1
  (m, gen3)  = random gen2
  [b',e',m'] = splitMod bitsize [b,e,m]
  r          = powModInteger b' e' m'
  res        = Map.fromList [("b", showHex b' ""),
                             ("e", showHex e' ""),
                             ("m", showHex m' ""),
                             ("r", showHex r  "")]


divTest :: Int -> StdGen -> (Map String String, StdGen)
divTest bitsize gen0 = (res, gen2)
 where
  (a, gen1) = random gen0
  (b, gen2) = random gen1
  a'        = a .&. mask bitsize
  b'        = b .&. mask bitsize
  (q, r)    = divMod a' b'
  res       = Map.fromList [("a", showHex a' ""),
                            ("b", showHex b' ""),
                            ("q", showHex q  ""),
                            ("r", showHex r  "")]

barrettGenTest :: Int -> StdGen -> (Map String String, StdGen)
barrettGenTest bitsize gen0 = (res, gen1)
 where
  (m, gen1) = random gen0
  m'        = m .&. mask bitsize
  k         = computeK m'
  u         = barrett bitsize m'
  res       = Map.fromList [("m", showHex m' ""),
                            ("k", showHex k  ""),
                            ("u", showHex u  "")]

barrettReduceTest :: Int -> StdGen -> (Map String String, StdGen)
barrettReduceTest bitsize gen0 = (res, gen2)
 where
  (m, gen1) = random gen0
  (x, gen2) = random gen1
  m'        = m .&. mask bitsize
  x'        = x .&. mask (min bitsize (2 * k * 64))
  k         = computeK m'
  u         = barrett bitsize m'
  r         = x' `mod` m'
  res       = Map.fromList [("m", showHex m' ""),
                            ("x", showHex x' ""),
                            ("k", showHex k  ""),
                            ("u", showHex u  ""),
                            ("r", showHex r  "")]

bmodexpTest :: Int -> StdGen -> (Map String String, StdGen)
bmodexpTest bitsize gen0 = (res, gen2)
 where
  (b, gen1)  = random gen0
  (e, gen2)  = random gen1
  (m, gen3)  = random gen2
  [b',e',m'] = splitMod bitsize [b,e,m]
  k         = computeK m'
  u         = barrett bitsize m'
  r          = powModInteger b' e' m'
  res        = Map.fromList [("b", showHex b' ""),
                             ("e", showHex e' ""),
                             ("m", showHex m' ""),
                             ("k", showHex k  ""),
                             ("u", showHex u  ""),
                             ("r", showHex r  "")]


barrett :: Int -> Integer -> Integer
barrett bitsize m = (b ^ (2 * k)) `div` m
 where
  b = 2 ^ 64
  k = computeK m

computeK :: Integer -> Int
computeK v = go 0 1
 where
  go k acc | v < acc   = k + 1
           | otherwise = go (k + 1) (acc * (2 ^ 64))

log :: String -> IO ()
log str =
  do putStr str
     hFlush stdout

generateData :: Handle -> (StdGen -> (Map String String, StdGen)) ->
                StdGen -> () ->
                IO StdGen
generateData hndl generator gen () =
  do let (res, gen') = generator gen
     forM_ (Map.toList res) $ \ (key,val) ->
       do hPutStrLn hndl (key ++ ": " ++ val)
     log "."
     return gen'

main :: IO ()
main =
  do args <- getArgs
     let tests = if null args
                   then testTypes
                   else filter (\ (name,_) -> name `elem` args) testTypes
     forM_ tests $ \ (testName, testFun) ->
       forM_ bitSizes $ \ bitsize ->
         do log ("Generating "++show bitsize++"-bit "++testName++" tests")
            withFile (testName ++ "U" ++ show bitsize ++ ".test") WriteMode $
               \ hndl ->
                 do gen <- newStdGen
                    foldM_ (generateData hndl (testFun bitsize))
                           gen
                           (replicate numTests ())
                    hClose hndl
                    log " done\n"
