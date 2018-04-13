{-# LANGUAGE ScopedTypeVariables #-}
import Control.Monad
import Data.Bits
import Data.List
import qualified Data.Map.Strict as Map
import GHC.Integer.GMP.Internals
import Numeric
import System.IO
import System.Random
import Debug.Trace

type Generator a = StdGen -> a -> (Maybe [(String, Integer)], a, StdGen)

iterations :: Int
iterations = 5000

maxSize :: Int
maxSize = 8

randomVal :: (Integer -> Bool) -> StdGen -> (Integer, StdGen)
randomVal filter g =
  let (mySize,   g')  = randomR (1, maxSize) g
      (possible, g'') = go g' mySize
  in if filter possible
        then (possible, g'')
        else randomVal filter g''
 where
  go rng 0 = (0, rng)
  go rng i =
    let (other, rng')  = go rng (i - 1)
        (self,  rng'') = random rng'
    in ((other `shiftL` 64) + self, rng'')

buildBasicGenerator :: (Integer -> Bool) ->
                       (Integer -> Integer -> Maybe Integer) ->
                       Generator ()
buildBasicGenerator filter f g () =
  let (x, g')   = randomVal filter g
      (y, g'')  = randomVal filter g'
  in case f x y of
       Nothing ->
         (Nothing, (), g'')
       Just z ->
         (Just [("x", x), ("y", y), ("z", z)], (), g'')

buildBasicLimitingGenerator :: (Integer -> Bool) ->
                               (Integer -> Integer -> Maybe Integer) ->
                               Generator (Map.Map Integer Int)
buildBasicLimitingGenerator filter f g m =
  let (x, g')   = randomVal filter g
      (y, g'')  = randomVal filter g'
  in case f x y of
       Nothing -> (Nothing, m, g'')
       Just z ->
         case Map.lookup z m of
           Nothing ->
             (Just [("x",x),("y",y),("z",z)], Map.insert z 1 m, g'')
           Just c | c >= 100 ->
             (Nothing, m, g'')
           Just c ->
             (Just [("x",x),("y",y),("z",z)], Map.insert z (c + 1) m, g'')

buildBasicAccGenerator :: (Integer -> Bool) ->
                          (Integer -> Integer -> a -> Maybe (Integer, a)) ->
                          Generator a
buildBasicAccGenerator filter f g acc =
  let (x, g')   = randomVal filter g
      (y, g'')  = randomVal filter g'
  in case f x y acc of
       Nothing ->
         (Nothing, acc, g'')
       Just (z, acc') ->
         (Just [("x", x), ("y", y), ("z", z)], acc', g'')

runGenerator :: forall a. StdGen -> String -> a -> Generator a -> IO StdGen
runGenerator g filename initVal generator =
   withFile (filename ++ ".tests") WriteMode $ \ hndl ->
     do putStrLn ("Generating " ++ filename ++ ".tests")
        go hndl g initVal iterations
 where
  go :: Handle -> StdGen -> a -> Int -> IO StdGen
  go _    g _   0          = return g
  go hndl g acc iterations =
    case generator g acc of
      (Nothing, acc', g')  ->
        go hndl g' acc' iterations
      (Just res, acc', g') ->
        do let sorted = sort res
           forM_ sorted $ \ (key, val) ->
             do let neg  = if val < 0 then "-" else ""
                    val' = abs val
                hPutStrLn hndl (key ++ ": " ++ neg ++ showHex val' "")
           go hndl g' acc' (iterations - 1)

main :: IO ()
main =
  do g0 <- newStdGen
     g1 <- runGenerator g0 "unsigned_add" () $
             buildBasicGenerator (>= 0) $ \ a b -> Just (a + b)
     g2 <- runGenerator g1 "signed_add" () $
             buildBasicGenerator (const True) $ \ a b -> Just (a + b)
     g3 <- runGenerator g2 "unsigned_sub" () $
             buildBasicGenerator (>= 0) $ \ a b ->
               if a >= b then Just (a - b) else Nothing
     g4 <- runGenerator g3 "signed_sub" () $
             buildBasicGenerator (const True) $ \ a b -> Just (a - b)
     g5 <- runGenerator g4 "unsigned_mul" () $
             buildBasicGenerator (>= 0) $ \ a b -> Just (a * b)
     g6 <- runGenerator g5 "signed_mul" () $
             buildBasicGenerator (const True) $ \ a b -> Just (a * b)
     g7 <- runGenerator g6 "unsigned_div" Map.empty $
             buildBasicLimitingGenerator (>= 0) $ \ a b ->
               if b == 0 then Nothing else Just (a `div` b)
     g8 <- runGenerator g7 "signed_div" Map.empty $
             buildBasicLimitingGenerator (const True) $ \ a b ->
               if b == 0 then Nothing else Just (a `div` b)
     g7 <- runGenerator g6 "unsigned_mod" 0 $
             buildBasicAccGenerator (>= 0) $ \ a b i ->
               case a `mod` b of
                 _ | b == 0                 -> Nothing
                 x | (a == x) && (i == 100) -> Nothing
                 x | a == x                 -> Just (x, i + 1)
                 x                          -> Just (x, i)
     g8 <- runGenerator g7 "signed_mod" 0 $
             buildBasicAccGenerator (const True) $ \ a b i ->
               case a `mod` b of
                 _ | b == 0                 -> Nothing
                 x | (a == x) && (i == 100) -> Nothing
                 x | a == x                 -> Just (x, i + 1)
                 x                          -> Just (x, i)
     g9 <- runGenerator g8 "modexp" () $ \ g () ->
             let (a, g')   = randomVal (>= 0) g
                 (b, g'')  = randomVal (>= 0) g'
                 (m, g''') = randomVal (>= 0) g''
                 z         = powModInteger a b m
                 res       = [("a",a),("b",b),("m",m),("z",z)]
             in if m == 0
                   then (Nothing, (), g''')
                   else (Just res, (), g''')
     _  <- runGenerator g9 "barrett" () $ \ g () ->
             let (m, g')  = randomVal (>= 0) g
                 (v, g'') = randomVal (>= 0) g'
                 barrett  = barrett_u m
                 vk       = computeK v
             in if vk > (2 * (bk barrett))
                   then (Nothing, (), g'')
                   else let me = reduce v barrett
                            standard = v `mod` m
                            res = [("m", m), ("v", v), ("r", me),
                                   ("u", bu barrett), ("k", fromIntegral (bk barrett))]
                        in if me /= standard
                              then error "Barrett broken"
                              else (Just res, (), g'')

     return ()

-- Implement Barrett reduction using incredibly simplistic implementations, to
-- be sure we got it right.
--
b :: Integer
b = 2 ^ 64

computeK :: Integer -> Int
computeK v = go 0 1
 where
  go k acc
    | v < acc   = k
    | otherwise = go (k + 1) (acc * b)

data Barrett = Barrett { bm :: Integer, bu :: Integer, bk :: Int }
 deriving (Show)

barrett_u :: Integer -> Barrett
barrett_u x = Barrett {
    bm = x,
    bu = (b ^ (2 * k)) `div` x,
    bk = k
  }
 where k = computeK x

reduce :: Integer -> Barrett -> Integer
reduce x barrett = result
  where
    k = bk barrett
    u = bu barrett
    m = bm barrett
    --
    q1 = x `div` (b ^ (k - 1))
    q2 = q1 * u
    q3 = q2 `div` (b ^ (k + 1))
    r1 = x `mod` (b ^ (k + 1))
    r2 = (q3 * m) `mod` (b ^ (k + 1))
    r = r1 - r2
    r' = if r < 0 then r + (b ^ (k + 1)) else r
    result = minimize r' m

minimize :: Integer -> Integer -> Integer
minimize r m | r < 0     = error "BLECH"
             | r >= m    = minimize (r - m) m
             | otherwise = r

-- runOperation :: Handle -> IO ()
-- runOperation hndl =
--   do m <- randomVal =<< randomRIO (1,size)
--      v <- randomVal =<< randomRIO (1,size)
--      let barrett = barrett_u m
--      let vk = computeK v
--      if vk > (2 * (bk barrett))
--         then runOperation hndl
--         else do hPutStrLn hndl ("m: " ++ showHex m "")
--                 hPutStrLn hndl ("k: " ++ show (bk barrett))
--                 hPutStrLn hndl ("u: " ++ show (bu barrett))
--                 let me = reduce v barrett
--                     standard = v `mod` m
--                 unless (me == standard) $
--                    fail "Barrett messed up."
--                 hPutStrLn hndl ("v: " ++ showHex v "")
--                 hPutStrLn hndl ("r: " ++ showHex me "")
--                 hFlush hndl
-- 
-- generateFile :: String ->
--                 IO ()
-- generateFile file =
--   withFile (file ++ "_tests.txt") WriteMode $ \ hndl ->
--     forM_ [0..2000] $ \ _ ->
--       runOperation hndl
-- 
-- main :: IO ()
-- main =
--   do generateFile "add" $ \ x y ->
--        (x, y, x + y)
--      generateFile "sub" $ \ x y ->
--        let x' = max x y
--            y' = min x y
--        in (x', y', x' - y')
--      generateFile "mul" $ \ x y ->
--        (x, y, x * y)
--      generateFile "div" $ \ x y ->
--        let y' = if y == 0 then 1 else y
--        in (x, y', x / y')
--      generateFile "mod" $ \ x y ->
--        let y' = if y == 0 then 1 else y
--        in (x, y', x / y')
--      generateFile "barrett"
