import Numeric

data Set = Set { r :: Integer, s :: Integer, t :: Integer }

step :: Set -> Set -> Set
step old new = Set r' s' t'
 where
  quotient = r old `div` r new
  r' = r old - (r new * quotient)
  s' = s old - (s new * quotient)
  t' = t old - (t new * quotient)

run :: Integer -> Integer -> IO Set
run self rhs = go (Set self 1 0) (Set rhs 0 1)
 where
  go old new | r new == 0 =
    do putStrLn "------------------------------"
       putStrLn ("res_r: " ++ showX (r old))
       putStrLn ("res_s: " ++ showX (s old))
       putStrLn ("res_t: " ++ showX (t old))
       return old
             | otherwise  =
    do putStrLn "------------------------------"
       putStrLn ("old_r: " ++ showX (r old))
       putStrLn ("old_s: " ++ showX (s old))
       putStrLn ("old_t: " ++ showX (t old))
       putStrLn ("new_r: " ++ showX (r new))
       putStrLn ("new_s: " ++ showX (s new))
       putStrLn ("new_t: " ++ showX (t new))
       go new (step old new)

showX :: Integer -> String
showX x | x < 0 = "-" ++ showX (abs x)
        | otherwise = showHex x ""
