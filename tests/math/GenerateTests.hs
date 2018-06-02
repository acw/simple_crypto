import Control.Monad
import Data.Bits(shiftL,(.&.))
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Numeric(showHex)
import Prelude hiding (log)
import System.IO(hFlush,stdout,IOMode(..),withFile,Handle,hClose,hPutStrLn)
import System.Random(StdGen,newStdGen,random)

testTypes :: [(String, Int -> StdGen -> (Map String String, StdGen))]
testTypes = [("addition", addTest),
             ("modadd", modaddTest),
             ("subtraction", subTest),
             ("multiplication", mulTest),
             ("expandingmul", expmulTest)
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
  forM_ testTypes $ \ (testName, testFun) ->
    forM_ bitSizes $ \ bitsize ->
      do log ("Generating " ++ show bitsize ++ "-bit " ++ testName ++ " tests")
         withFile (testName ++ "U" ++ show bitsize ++ ".test") WriteMode $ \ hndl ->
           do gen <- newStdGen
              foldM_ (generateData hndl (testFun bitsize))
                     gen
                     (replicate numTests ())
              hClose hndl
              log " done\n"
