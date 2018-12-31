{-# LANGUAGE RecordWildCards #-}
module Math(
         extendedGCD
       , barrett, computeK, base
       , modulate, modulate'
       , isqrt
       , divmod
       , showX, showB
       )
 where

import Data.Bits(shiftL,shiftR)
import GHC.Integer.GMP.Internals(recipModInteger)
import Numeric(showHex)

data AlgState = AlgState {
    u    :: Integer,
    v    :: Integer,
    bigA :: Integer,
    bigB :: Integer,
    bigC :: Integer,
    bigD :: Integer
}

printState :: AlgState -> IO ()
printState a =
  do putStrLn ("u: " ++ showX (u a))
     putStrLn ("v: " ++ showX (v a))
     putStrLn ("A: " ++ showX (bigA a))
     putStrLn ("B: " ++ showX (bigB a))
     putStrLn ("C: " ++ showX (bigC a))
     putStrLn ("D: " ++ showX (bigD a))

extendedGCD :: Integer -> Integer -> (Integer, Integer, Integer)
extendedGCD x y = (a, b, g * (v finalState))
  where
    (x', y', g, initState) = initialState x y 1
    finalState             = runAlgorithm x' y' initState
    a                      = bigC finalState
    b                      = bigD finalState

initialState :: Integer -> Integer -> Integer -> (Integer, Integer, Integer, AlgState)
initialState x y g | even x && even y = initialState (x `div` 2) (y `div` 2) (g * 2)
                   | otherwise        = (x, y, g, AlgState x y 1 0 0 1)

runAlgorithm :: Integer -> Integer -> AlgState -> AlgState
runAlgorithm x y state | u state == 0 = state
                       | otherwise    = runAlgorithm x y state6
  where
    state4 = step4 x y state
    state5 = step5 x y state4
    state6 = step6     state5

step4 :: Integer -> Integer -> AlgState -> AlgState
step4 x y input@AlgState{..} | even u    = step4 x y input'
                             | otherwise = input
  where
    input' = AlgState u' v bigA' bigB' bigC bigD
    u'     = u `div` 2
    bigA' | even bigA && even bigB = bigA `div` 2
          | otherwise              = (bigA + y) `div` 2
    bigB' | even bigA && even bigB = bigB `div` 2
          | otherwise              = (bigB - x) `div` 2

step5 :: Integer -> Integer -> AlgState -> AlgState
step5 x y input@AlgState{..} | even v    = step5 x y input'
                             | otherwise = input
  where
    input' = AlgState u v' bigA bigB bigC' bigD'
    v'     = v `div` 2
    bigC' | even bigC && even bigD = bigC `div` 2
          | otherwise              = (bigC + y) `div` 2
    bigD' | even bigC && even bigD = bigD `div` 2
          | otherwise              = (bigD - x) `div` 2

step6 :: AlgState -> AlgState
step6 AlgState{..}
  | u >= v    = AlgState (u - v) v (bigA - bigC) (bigB - bigD) bigC bigD
  | otherwise = AlgState u (v - u) bigA bigB (bigC - bigA) (bigD - bigB)

barrett :: Integer -> Integer
barrett m = (base ^ (2 * k)) `div` m
 where
  k = computeK m

computeK :: Integer -> Int
computeK v = go 0 1
 where
  go k acc | v <= acc  = k
           | otherwise = go (k + 1) (acc * base)

base :: Integer
base = 2 ^ (64 :: Integer)

modulate :: Integer -> Int -> Integer
modulate x size = x `mod` (2 ^ size)

modulate' :: Integer -> Int -> Integer
modulate' x size = signum x * (abs x `mod` (2 ^ size))

showX :: (Integral a, Show a) => a -> String
showX x | x < 0     = "-" ++ showX (abs x)
        | otherwise = showHex x ""

showB :: Bool -> String
showB False = "0"
showB True  = "1"

isqrt :: Int -> Integer -> Integer
isqrt bits val = final
  where
   bit' = part1 (1 `shiftL` (bits - 2))
   --
   part1 x | x > val   = part1 (x `shiftR` 2)
           | otherwise = x
   --
   final = loop val 0 bit'
   --
   loop num res bit
     | bit == 0 = res
     | otherwise = let (num', res') = adjust num res bit
                   in loop num' (res' `shiftR` 1) (bit `shiftR` 2)
   adjust num res bit
     | num >= (res + bit) = (num - (res + bit), res + (bit `shiftL` 1))
     | otherwise          = (num, res)

divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod x y m =
  let y' = y `mod` m
  in case recipModInteger y' m of
       0 -> Nothing
       i -> Just ((x * i) `mod` m)

_run :: Integer -> Integer -> IO ()
_run inputx inputy =
  do let (x, y, g, initState) = initialState inputx inputy 1
     finalState <- go x y initState
     putStrLn ("-- FINAL STATE -----------------------")
     printState finalState
     putStrLn ("Final value: " ++ showX (g * v finalState))
     putStrLn ("-- RUN ------")
     printState (runAlgorithm x y initState)
     putStrLn ("-- NORMAL ------")
     let (a, b, v) = extendedGCD inputx inputy
     putStrLn ("a: " ++ showX a)
     putStrLn ("b: " ++ showX b)
     putStrLn ("v: " ++ showX v)

 where
  go x y state =
    do putStrLn "-- STATE -----------------------------"
       printState state
       if u state == 0
          then return state
          else do let state'   = step4 x y state
                      state''  = step5 x y state'
                      state''' = step6     state''
                  go x y state'''
