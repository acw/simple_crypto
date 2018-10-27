import Data.Bits
import Numeric

a :: Integer
a = 0xffffffffffffffffffffffffffffffffa275ec6d0ffbb359

b :: Integer
b = 0xffffffffffffffffffffffffffffffffa14e39a19260951d

outs :: Integer
outs = -0x9124a315de33a9

outt :: Integer
outt = 0x180b603717d35f66

outg :: Integer
outg = 1

x :: Integer
y :: Integer
g :: Integer
(x, y, g) = loop a b 1
 where loop x y g
         | even x && even y = loop (x `shiftR` 1) (y `shiftR` 1) (g `shiftL` 1)
         | otherwise        = (x, y, g)

u0 :: Integer
u0 = x

v0 :: Integer
v0 = y

bigA0 :: Integer
bigA0 =  1

bigB0 :: Integer
bigB0 =  0

bigC0 :: Integer
bigC0 =  0

bigD0 :: Integer
bigD0 =  1

step4 :: (Integer, Integer, Integer, Integer, Integer, Integer) ->
         (Integer, Integer, Integer, Integer, Integer, Integer)
step4 (u, v, bigA, bigB, bigC, bigD) = (resu, v, resA, resB, bigC, bigD)
 where
   (resu, resA, resB) = step4 u bigA bigB
   step4 inu inA inB
     | even inu = let outu = inu `div` 2
                  in if even inA && even inB
                       then step4 outu (inA `div` 2) (inB `div` 2)
                       else step4 outu ((inA + y) `div` 2) ((inB - x) `div` 2)
     | otherwise = (inu, inA, inB)

step5 :: (Integer, Integer, Integer, Integer, Integer, Integer) ->
         (Integer, Integer, Integer, Integer, Integer, Integer)
step5 (u, v, bigA, bigB, bigC, bigD) = (u, resv, bigA, bigB, resC, resD)
 where
   (resv, resC, resD) = step5 v bigC bigD
   step5 inv inC inD
     | even inv = let outv = inv `div` 2
                  in if even inC && even inD
                       then step5 outv (inC `div` 2) (inD `div` 2)
                       else step5 outv ((inC + y) `div` 2) ((inD - x) `div` 2)
     | otherwise = (inv, inC, inD)

step6 :: (Integer, Integer, Integer, Integer, Integer, Integer) ->
         (Integer, Integer, Integer, Integer, Integer, Integer)
step6 (u, v, bigA, bigB, bigC, bigD)
  | u >= v    = (u - v, v, bigA - bigC, bigB - bigD, bigC, bigD)
  | otherwise = (u, v - u, bigA, bigB, bigC - bigA, bigD - bigB)

iteration :: (Integer, Integer, Integer, Integer, Integer, Integer) ->
             (Integer, Integer, Integer, Integer, Integer, Integer)
iteration = step6 . step5 . step4

state0 :: (Integer, Integer, Integer, Integer, Integer, Integer)
state0 = (u0, v0, bigA0, bigB0, bigC0, bigD0)

printIter :: (Integer, Integer, Integer, Integer, Integer, Integer) -> IO ()
printIter (u, v, a, b, c, d) =
  do printVal "u" u
     printVal "v" v
     printVal "A" a
     printVal "B" b
     printVal "C" c
     printVal "D" d

printVal :: String -> Integer -> IO ()
printVal name x =
  do putStr (name ++ ": ")
     if x < 0
        then putStr "-"
        else putStr " "
     let x' = abs x
     putStrLn (showHex x' "")

myImpl inState | u == 0    = outState
               | otherwise = myImpl outState
 where
  outState@(u,_,_,_,_,_) = iteration inState

