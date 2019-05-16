{-# LANGUAGE PackageImports #-}
module ED25519(ed25519Tasks)
 where

import Control.Monad(unless)
import Crypto.Error(CryptoFailable(CryptoPassed))
import "crypto-api" Crypto.Random(SystemRandom)
import "cryptonite" Crypto.Random(getRandomBytes,withDRG)
import Crypto.PubKey.Ed25519
import Data.ByteArray(convert)
import Data.ByteString(ByteString,pack,useAsCString)
import qualified Data.ByteString as BS
import Data.Int(Int32)
import qualified Data.Map.Strict as Map
import Data.Word(Word8,Word32,Word64)
import ED25519.PrecompPoints
import Foreign.C.Types(CChar)
import Foreign.Marshal.Alloc(alloca)
import Foreign.Marshal.Array(allocaArray,peekArray,pokeArray)
import Foreign.Ptr(Ptr,castPtr)
import Foreign.Storable(Storable(..))
import Math(showX,showBin)
import Task(Task(..))

cTEST_COUNT :: Int
cTEST_COUNT = 1000

ed25519Tasks :: [Task]
ed25519Tasks = [ loadTests, byteTests, addsubTests, mulTests,
                  squaringTests, inversionTests, negateTests,
                  cmovTests, isTests, square2Tests,
                  pow22523Tests, fbvTests, conversionTests,
                  ptDoubleTests, maddsubTests, ptAddSubTests,
                  scalarMultBaseTests, slideTests, scalarMultTests,
                  reduceTests, muladdTests, pubPrivTests,
                  signTest ]

loadTests :: Task
loadTests = Task {
    taskName = "ed25519 byte loading",
    taskFile = "../testdata/ed25519/load.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) = 
    do let (bytes, drg1) = withDRG drg0 (getRandomBytes 4)
       res3 <- useAsCString bytes (\ptr -> load_3 ptr)
       res4 <- useAsCString bytes (\ptr -> load_4 ptr)
       let res = Map.fromList [("x", showBin bytes), ("a", showX res3), ("b", showX res4)]
       return (res, fromIntegral res4, (memory0, drg1))

byteTests :: Task
byteTests = Task {
    taskName = "ed25519 byte / element conversion",
    taskFile = "../testdata/ed25519/bytes.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPackedBytes drg0 $ \ ptra drg1 ->
      alloca $ \ ptrc ->
        allocaArray 32 $ \ rptr ->
          do clearSpace ptrc
             pokeArray (rptr :: Ptr Word8) (replicate 32 0)
             fe_frombytes ptrc ptra
             b <- convertFE ptrc
             fe_tobytes (castPtr rptr) ptrc
             start <- peek ptra
             end   <- peek (castPtr rptr)
             unless (start == end) $
               fail "field element tobytes/frombytes doesn't round trip"
             bytes' <- pack `fmap` peekArray 32 (castPtr ptra :: Ptr Word8)
             let res = Map.fromList [("a", showBin bytes'),
                                     ("b", showBin b)]
             return (res, toNumber b, (memory0, drg1))

addsubTests :: Task
addsubTests = Task {
    taskName = "ed25519 addition/subtraction tests",
    taskFile = "../testdata/ed25519/addsub.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ ptrel1 drg1 ->
      randomElement drg1 $ \ ptrel2 drg2 ->
        alloca $ \ ptrc ->
          alloca $ \ ptrd ->
            do fe_add ptrc ptrel1 ptrel2
               fe_sub ptrd ptrel1 ptrel2
               [a, b, c, d] <- mapM convertFE [ptrel1, ptrel2, ptrc, ptrd] 
               let res = Map.fromList [("a", showBin a),
                                       ("b", showBin b),
                                       ("c", showBin c),
                                       ("d", showBin d)]
               return (res, toNumber c, (memory0, drg2))

mulTests :: Task
mulTests = Task {
    taskName = "ed25519 multiplication tests",
    taskFile = "../testdata/ed25519/mul.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ ptrel1 drg1 ->
      randomElement drg1 $ \ ptrel2 drg2 ->
        alloca $ \ ptrc ->
          do fe_mul ptrc ptrel1 ptrel2
             [a, b, c] <- mapM convertFE [ptrel1, ptrel2, ptrc] 
             let res = Map.fromList [("a", showBin a),
                                     ("b", showBin b),
                                     ("c", showBin c)]
             return (res, toNumber c, (memory0, drg2))

squaringTests :: Task
squaringTests = Task {
    taskName = "ed25519 squaring tests",
    taskFile = "../testdata/ed25519/square.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ ptrel drg1 ->
      alloca $ \ ptrc ->
        do fe_square ptrc ptrel
           [a, c] <- mapM convertFE [ptrel, ptrc]
           let res = Map.fromList [("a", showBin a),
                                   ("c", showBin c)]
           return (res, toNumber c, (memory0, drg1))

inversionTests :: Task
inversionTests = Task {
    taskName = "ed25519 inversion tests",
    taskFile = "../testdata/ed25519/invert.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ ptrel drg1 ->
      alloca $ \ ptrc ->
        do fe_invert ptrc ptrel
           a <- convertFE ptrel
           c <- convertFE ptrc
           let res = Map.fromList [("a", showBin a),
                                   ("c", showBin c)]
           return (res, toNumber a, (memory0, drg1))

negateTests :: Task
negateTests = Task {
    taskName = "ed25519 negation tests",
    taskFile = "../testdata/ed25519/negate.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ ptrel drg1 ->
      alloca $ \ ptrc ->
        do fe_negate ptrc ptrel
           a <- convertFE ptrel
           c <- convertFE ptrc
           let res = Map.fromList [("a", showBin a),
                                   ("c", showBin c)]
           return (res, toNumber a, (memory0, drg1))

cmovTests :: Task
cmovTests = Task {
    taskName = "ed25519 conditional mov tests",
    taskFile = "../testdata/ed25519/cmov.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ aelptr drg1 ->
      do let (bbytes, drg2) = withDRG drg1 (getRandomBytes 1)
             b              = even (BS.head bbytes)
             bvalLib        = if b then 0 else 1
             bvalOut        = if b then 0 else 0xFFFFFF :: Word32
         alloca $ \ celptr ->
           do clearSpace celptr
              fe_cmov celptr aelptr bvalLib
              a <- convertFE aelptr
              c <- convertFE celptr
              let res = Map.fromList [("a", showBin a),
                                      ("b", showX   bvalOut),
                                      ("c", showBin c)]
              return (res, toNumber a, (memory0, drg2))

isTests :: Task
isTests = Task {
    taskName = "ed25519 predicate tests",
    taskFile = "../testdata/ed25519/istests.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ aptr drg1 ->
      do a <- convertFE aptr
         z <- fe_isnonzero aptr
         n <- fe_isnegative aptr
         let res = Map.fromList [("a", showBin a),
                                 ("z", showX (if z == 0 then 0 :: Word32 else 0xFFFFFF)),
                                 ("n", showX (if n == 0 then 0 :: Word32 else 0xFFFFFF))]
         return (res, toNumber a, (memory0, drg1))

square2Tests :: Task
square2Tests = Task {
    taskName = "ed25519 square2 tests",
    taskFile = "../testdata/ed25519/square2.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) = 
    randomElement drg0 $ \ aptr drg1 ->
      alloca $ \ cptr ->
        do clearSpace cptr
           fe_square2 cptr aptr
           a <- convertFE aptr
           c <- convertFE cptr
           let res = Map.fromList [("a", showBin a), ("c", showBin c)]
           return (res, toNumber a, (memory0, drg1))

pow22523Tests :: Task
pow22523Tests = Task {
    taskName = "ed25519 pow22523 tests",
    taskFile = "../testdata/ed25519/pow22523.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomElement drg0 $ \ aptr drg1 ->
      alloca $ \ cptr ->
        do clearSpace cptr
           fe_pow22523 cptr aptr
           a <- convertFE aptr
           c <- convertFE cptr
           let res = Map.fromList [("a", showBin a), ("c", showBin c)]
           return (res, toNumber a, (memory0, drg1))

fbvTests :: Task
fbvTests = Task {
    taskName = "ed25519 from bytes (vartime) tests",
    taskFile = "../testdata/ed25519/fbv.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) = 
    do let (abytes, drg1) = withDRG drg0 (getRandomBytes 32)
       useAsCString abytes $ \ aptr ->
         do let aptr' = castPtr aptr :: Ptr PackedBytes
            curve25519_scalar_mask aptr'
            alloca $ \ dest ->
              do clearSpace dest
                 point_frombytes dest aptr'
                 a <- pack `fmap` peekArray 32 (castPtr aptr)
                 c <- pack `fmap` peekArray (4 * 10 * 4) (castPtr dest)
                 let res = Map.fromList [("a", showBin a), ("c", showBin c)]
                 return (res, toNumber abytes, (memory0, drg1))

conversionTests :: Task
conversionTests = Task {
    taskName = "ed25519 point form conversion tests",
    taskFile = "../testdata/ed25519/conversion.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPoint3 drg0 $ \ ptr3 drg' ->
      alloca $ \ ptrCached ->
        alloca $ \ ptr2 ->
          alloca $ \ ptrP1P1 ->
            alloca $ \ ptr2' ->
              alloca $ \ ptr3' ->
                do clearSpace ptrCached
                   clearSpace ptr2
                   clearSpace ptrP1P1
                   clearSpace ptr2'
                   clearSpace ptr3'
                   p3_to_cached ptrCached ptr3
                   ge_p3_to_p2  ptr2      ptr3
                   ge_p3_dbl    ptrP1P1   ptr3
                   p1p1_to_p2   ptr2'     ptrP1P1
                   p1p1_to_p3   ptr3'     ptrP1P1
                   a <- convertPoint ptr3
                   c <- convertPoint ptrCached
                   t <- convertPoint ptr2
                   o <- convertPoint ptrP1P1
                   d <- convertPoint ptr2'
                   b <- convertPoint ptr3'
                   let res = Map.fromList [("a", showBin a), ("c", showBin c),
                                           ("t", showBin t), ("o", showBin o),
                                           ("d", showBin d), ("b", showBin b)]
                   return (res, toNumber a, (memory0, drg'))

ptDoubleTests :: Task
ptDoubleTests = Task {
    taskName = "ed25519 point doubling tests",
    taskFile = "../testdata/ed25519/pt_double.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPoint3 drg0 $ \ ptra drg1 ->
      randomPoint2 drg1 $ \ ptrc drg2 ->
        alloca $ \ ptrb ->
          alloca $ \ ptrd ->
            do clearSpace ptrb
               clearSpace ptrd
               ge_p3_dbl ptrb ptra
               ge_p2_dbl ptrd ptrc
               a <- convertPoint ptra
               b <- convertPoint ptrb
               c <- convertPoint ptrc
               d <- convertPoint ptrd
               let res = Map.fromList [("a", showBin a), ("b", showBin b),
                                       ("c", showBin c), ("d", showBin d)]
               return (res, toNumber a, (memory0, drg2))

maddsubTests :: Task
maddsubTests = Task {
    taskName = "ed25519 point madd/msub tests",
    taskFile = "../testdata/ed25519/maddsub.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPoint3 drg0 $ \ ptra drg1 ->
      randomPointPrecomp drg1 $ \ ptrc drg2 ->
        alloca $ \ ptrb ->
          alloca $ \ ptrd ->
            do clearSpace ptrb
               clearSpace ptrd
               ge_madd ptrb ptra ptrc
               ge_msub ptrd ptra ptrc
               a <- convertPoint ptra
               b <- convertPoint ptrb
               c <- convertPoint ptrc
               d <- convertPoint ptrd
               let res = Map.fromList [("a", showBin a), ("b", showBin b),
                                       ("c", showBin c), ("d", showBin d)]
               return (res, toNumber a, (memory0, drg2))

ptAddSubTests :: Task
ptAddSubTests = Task {
    taskName = "ed25519 point add/sub tests",
    taskFile = "../testdata/ed25519/ptaddsub.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPoint3 drg0 $ \ ptra drg1 ->
      randomPointCached drg1 $ \ ptrc drg2 ->
        alloca $ \ ptrb ->
          alloca $ \ ptrd ->
            do clearSpace ptrb
               clearSpace ptrd
               ge_add ptrb ptra ptrc
               ge_sub ptrd ptra ptrc
               a <- convertPoint ptra
               b <- convertPoint ptrb
               c <- convertPoint ptrc
               d <- convertPoint ptrd
               let res = Map.fromList [("a", showBin a), ("b", showBin b),
                                       ("c", showBin c), ("d", showBin d)]
               return (res, toNumber a, (memory0, drg2))

scalarMultBaseTests :: Task
scalarMultBaseTests = Task {
    taskName = "ed25519 point add/sub tests",
    taskFile = "../testdata/ed25519/scalar_mult.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPackedBytes drg0 $ \ ptra drg1 ->
      alloca $ \ ptrb ->
        do clearSpace ptrb
           x25519_ge_scalarmult_base ptrb ptra
           PB abytes <- peek ptra
           let a = pack abytes
           b <- convertPoint ptrb
           let res = Map.fromList [("a", showBin a), ("b", showBin b)]
           return (res, toNumber a, (memory0, drg1))

slideTests :: Task
slideTests = Task {
    taskName = "ed25519 slide helper function tests",
    taskFile = "../testdata/ed25519/slide.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPackedBytes drg0 $ \ ptra drg1 ->
      allocaArray 256 $ \ ptrb ->
        do pokeArray ptrb (replicate 256 0)
           slide ptrb ptra
           a <- pack `fmap` peekArray 32 (castPtr ptra)
           b <- pack `fmap` peekArray 356 ptrb 
           let res = Map.fromList [("a", showBin a), ("b", showBin b)]
           return (res, toNumber a, (memory0, drg1))

scalarMultTests :: Task
scalarMultTests = Task {
    taskName = "ed25519 point general scalar multiplication tests",
    taskFile = "../testdata/ed25519/scalar_mult_gen.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPackedBytes drg0 $ \ ptra drg1 ->
      randomPoint3 drg1 $ \ ptrb drg2 ->
        randomPackedBytes drg2 $ \ ptrc drg3 ->
          alloca $ \ ptrd ->
            do clearSpace ptrd
               ge_double_scalarmult_vartime ptrd ptra ptrb ptrc
               PB abytes <- peek ptra
               let a = pack abytes
               b <- convertPoint ptrb
               PB cbytes <- peek ptrc
               let c = pack cbytes
               d <- convertPoint ptrd
               let res = Map.fromList [("a", showBin a), ("b", showBin b),
                                       ("c", showBin c), ("d", showBin d)]
               return (res, toNumber a, (memory0, drg3))

reduceTests :: Task
reduceTests = Task {
    taskName = "ed25519 reduce tests",
    taskFile = "../testdata/ed25519/reduce.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    do let (a, drg1) = withDRG drg0 (getRandomBytes 64)
       allocaArray 64 $ \ target ->
         do pokeArray target (BS.unpack a)
            sc_reduce target
            b <- pack `fmap` peekArray 32 target
            let res = Map.fromList [("a", showBin a), ("b", showBin b)]
            return (res, toNumber a, (memory0, drg1))

muladdTests :: Task
muladdTests = Task {
    taskName = "ed25519 multiplication+addition tests",
    taskFile = "../testdata/ed25519/muladd.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPackedBytes drg0 $ \ ptra drg1 ->
      randomPackedBytes drg1 $ \ ptrb drg2 ->
        randomPackedBytes drg2 $ \ ptrc drg3 ->
          alloca $ \ ptrd ->
            do clearSpace ptrd
               sc_muladd ptrd ptra ptrb ptrc
               a <- repackBytes ptra
               b <- repackBytes ptrb
               c <- repackBytes ptrc
               d <- repackBytes ptrd
               let res = Map.fromList [("a", showBin a), ("b", showBin b),
                                       ("c", showBin c), ("d", showBin d)]
               return (res, toNumber a, (memory0, drg3))

pubPrivTests :: Task
pubPrivTests = Task {
    taskName = "ed25519 private -> public conversion tests",
    taskFile = "../testdata/ed25519/pubfrompriv.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    randomPackedBytes drg0 $ \ ptra drg1 ->
      alloca $ \ ptrb ->
        do clearSpace ptrb
           public_from_private ptrb ptra
           a <- repackBytes ptra
           b <- repackBytes ptrb
           let res = Map.fromList [("a", showBin a), ("b", showBin b)]
           return (res, toNumber a, (memory0, drg1))

signTest :: Task
signTest = Task {
    taskName = "ed25519 signing tests",
    taskFile = "../testdata/ed25519/sign.test",
    taskTest = go,
    taskCount = cTEST_COUNT
  }
 where
  go (memory0, drg0) =
    let (priv, drg1) = withDRG drg0 generateSecretKey
        (msg, drg2) = withDRG drg1 $ getRandomBytes =<< ((fromIntegral . BS.head) `fmap` getRandomBytes 1)
        pub = toPublic priv
        privBytes = convert priv
        pubBytes = convert pub
        sig = convert (sign priv pub msg)
        res = Map.fromList [("u", showBin pubBytes), ("r", showBin privBytes),
                            ("m", showBin msg), ("s", showBin sig)]
    in return (res, toNumber privBytes, (memory0, drg2))


data PackedBytes = PB [Word8]
 deriving (Eq)

instance Storable PackedBytes where
  sizeOf    _        = 32
  alignment _        = 8
  peek      p        = PB `fmap` peekArray 32 (castPtr p)
  poke      p (PB v) = pokeArray    (castPtr p) v

randomPackedBytes :: SystemRandom -> (Ptr PackedBytes -> SystemRandom -> IO a) -> IO a
randomPackedBytes drg action =
  do let (bytes, drg') = withDRG drg (getRandomBytes 32)
     useAsCString bytes $ \ ptr ->
       do let ptr' = castPtr ptr :: Ptr PackedBytes
          curve25519_scalar_mask ptr'
          action ptr' drg'

repackBytes :: Ptr PackedBytes -> IO ByteString
repackBytes ptr =
  do PB xs <- peek ptr
     return (pack xs)

data Element = FE [Int32]

instance Storable Element where
  sizeOf    _        = 10 * sizeOf (undefined :: Int32)
  alignment _        = 8
  peek      p        = FE `fmap` peekArray 10 (castPtr p)
  poke      p (FE v) = pokeArray (castPtr p) v

randomElement :: SystemRandom -> (Ptr Element -> SystemRandom -> IO a) -> IO a
randomElement drg action =
  randomPackedBytes drg $ \ ptrpb drg' -> alloca $ \ ptrel ->
    do clearSpace ptrel
       fe_frombytes ptrel ptrpb
       action ptrel drg'

data Point3 = P3 [Element]

instance Storable Point3 where
  sizeOf    _        = 4 * sizeOf (undefined :: Element)
  alignment _        = 8
  peek      p        = P3 `fmap` peekArray 4 (castPtr p)
  poke      p (P3 v) = pokeArray (castPtr p) v

randomPoint3 :: SystemRandom -> (Ptr Point3 -> SystemRandom -> IO a) -> IO a
randomPoint3 drg action =
  randomPackedBytes drg $ \ aptr drg' ->
    allocaArray (4 * 10) $ \ dest ->
      do clearSpace dest
         point_frombytes dest aptr
         action (castPtr dest) drg'

data PointCached = PC [Element]

instance Storable PointCached where
  sizeOf    _        = 4 * sizeOf (undefined :: Element)
  alignment _        = 8
  peek      p        = PC `fmap` peekArray 4 (castPtr p)
  poke      p (PC v) = pokeArray (castPtr p) v

randomPointCached :: SystemRandom -> (Ptr PointCached -> SystemRandom -> IO a) -> IO a
randomPointCached drg action =
  randomPoint3 drg $ \ ptr drg' ->
    allocaArray (4 * 10) $ \ dest ->
      do pokeArray (castPtr dest :: Ptr Int32) (replicate (4 * 10) 0)
         p3_to_cached dest ptr
         action (castPtr dest) drg'

data Point2 = P2 [Element]

instance Storable Point2 where
  sizeOf    _        = 3 * sizeOf (undefined :: Element)
  alignment _        = 8
  peek      p        = P2 `fmap` peekArray 3 (castPtr p)
  poke      p (P2 v) = pokeArray (castPtr p) v

randomPoint2 :: SystemRandom -> (Ptr Point2 -> SystemRandom -> IO a) -> IO a
randomPoint2 drg action =
  randomPoint3 drg $ \ ptr3 drg' ->
    allocaArray (3 * 10) $ \ dest ->
      do pokeArray (castPtr dest :: Ptr Int32) (replicate (3 * 10) 0)
         ge_p3_to_p2 dest ptr3
         action (castPtr dest) drg'

data PointP1P1 = P1P1 [Element]

instance Storable PointP1P1 where
  sizeOf    _          = 4 * sizeOf (undefined :: Element)
  alignment _          = 8
  peek      p          = P1P1 `fmap` peekArray 4 (castPtr p)
  poke      p (P1P1 v) = pokeArray (castPtr p) v

_randomPointP1P1 :: SystemRandom -> (Ptr PointP1P1 -> SystemRandom -> IO a) -> IO a
_randomPointP1P1 drg action =
  randomPoint3 drg $ \ ptr3 drg' ->
    allocaArray (4 * 10) $ \ dest ->
      do pokeArray (castPtr dest :: Ptr Int32) (replicate (4 * 10) 0)
         ge_p3_dbl dest ptr3
         action (castPtr dest) drg'

data PointPrecomp = PP [Element]

instance Storable PointPrecomp where
  sizeOf    _        = 4 * sizeOf (undefined :: Element)
  alignment _        = 8
  peek      p        = PP `fmap` peekArray 4 (castPtr p)
  poke      p (PP v) = pokeArray (castPtr p) v

randomPointPrecomp :: SystemRandom -> (Ptr PointPrecomp -> SystemRandom -> IO a) -> IO a
randomPointPrecomp drg action =
  do let ([a,b,c,d], drg') = withDRG drg (BS.unpack `fmap` getRandomBytes 4)
         mix = fromIntegral a + fromIntegral b + fromIntegral c + fromIntegral d
         idx = mix `mod` (length precompPoints)
         val = PP (map FE (precompPoints !! idx))
     alloca $ \ ptr ->
       do poke ptr val
          action ptr drg'
      
clearSpace :: Storable a => Ptr a -> IO ()
clearSpace x = meh x undefined
 where
  meh :: Storable a => Ptr a -> a -> IO ()
  meh p v = pokeArray (castPtr p) (replicate (sizeOf v) (0 :: Word8))

convertFE :: Ptr Element -> IO ByteString
convertFE feptr = pack `fmap` peekArray 40 (castPtr feptr :: Ptr Word8)

convertPoint :: Storable a => Ptr a -> IO ByteString
convertPoint x = meh x undefined
 where
  meh :: Storable a => Ptr a -> a -> IO ByteString
  meh p v = pack `fmap` peekArray (sizeOf v) (castPtr p)

toNumber :: ByteString -> Integer
toNumber = BS.foldr (\ x a -> fromIntegral x + a) 0

foreign import ccall unsafe "load_3"
  load_3 :: Ptr CChar -> IO Word64
foreign import ccall unsafe "load_4"
  load_4 :: Ptr CChar -> IO Word64
foreign import ccall unsafe "GFp_curve25519_scalar_mask"
  curve25519_scalar_mask :: Ptr PackedBytes -> IO ()
foreign import ccall unsafe "fe_frombytes"
  fe_frombytes :: Ptr Element -> Ptr PackedBytes -> IO ()
foreign import ccall unsafe "GFp_fe_tobytes"
  fe_tobytes :: Ptr PackedBytes -> Ptr Element -> IO ()
foreign import ccall unsafe "fe_add"
  fe_add :: Ptr Element -> Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "fe_sub"
  fe_sub :: Ptr Element -> Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "GFp_fe_mul"
  fe_mul :: Ptr Element -> Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "fe_sq"
  fe_square :: Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "GFp_fe_invert"
  fe_invert :: Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "fe_neg"
  fe_negate :: Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "fe_cmov"
  fe_cmov :: Ptr Element -> Ptr Element -> Word32 -> IO ()
foreign import ccall unsafe "fe_isnonzero"
  fe_isnonzero :: Ptr Element -> IO Int32
foreign import ccall unsafe "GFp_fe_isnegative"
  fe_isnegative :: Ptr Element -> IO Word8
foreign import ccall unsafe "fe_sq2"
  fe_square2 :: Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "fe_pow22523"
  fe_pow22523 :: Ptr Element -> Ptr Element -> IO ()
foreign import ccall unsafe "GFp_x25519_ge_frombytes_vartime"
  point_frombytes :: Ptr Point3 -> Ptr PackedBytes -> IO ()
foreign import ccall unsafe "x25519_ge_p3_to_cached"
  p3_to_cached :: Ptr PointCached -> Ptr Point3 -> IO ()
foreign import ccall unsafe "x25519_ge_p1p1_to_p2"
  p1p1_to_p2 :: Ptr Point2 -> Ptr PointP1P1 -> IO ()
foreign import ccall unsafe "x25519_ge_p1p1_to_p3"
  p1p1_to_p3 :: Ptr Point3 -> Ptr PointP1P1 -> IO ()
foreign import ccall unsafe "ge_p2_dbl"
  ge_p2_dbl :: Ptr PointP1P1 -> Ptr Point2 -> IO ()
foreign import ccall unsafe "ge_p3_dbl"
  ge_p3_dbl :: Ptr PointP1P1 -> Ptr Point3 -> IO ()
foreign import ccall unsafe "ge_p3_to_p2"
  ge_p3_to_p2 :: Ptr Point2 -> Ptr Point3 -> IO ()
foreign import ccall unsafe "ge_madd"
  ge_madd :: Ptr PointP1P1 -> Ptr Point3 -> Ptr PointPrecomp -> IO ()
foreign import ccall unsafe "ge_msub"
  ge_msub :: Ptr PointP1P1 -> Ptr Point3 -> Ptr PointPrecomp -> IO ()
foreign import ccall unsafe "x25519_ge_add"
  ge_add :: Ptr PointP1P1 -> Ptr Point3 -> Ptr PointCached -> IO ()
foreign import ccall unsafe "x25519_ge_sub"
  ge_sub :: Ptr PointP1P1 -> Ptr Point3 -> Ptr PointCached -> IO ()
foreign import ccall unsafe "GFp_x25519_ge_scalarmult_base"
  x25519_ge_scalarmult_base :: Ptr Point3 -> Ptr PackedBytes -> IO ()
foreign import ccall unsafe "slide"
  slide :: Ptr Word8 -> Ptr PackedBytes -> IO ()
foreign import ccall unsafe "GFp_ge_double_scalarmult_vartime"
  ge_double_scalarmult_vartime :: Ptr Point2 -> Ptr PackedBytes -> Ptr Point3 -> Ptr PackedBytes -> IO ()
foreign import ccall unsafe "GFp_x25519_sc_reduce"
  sc_reduce :: Ptr Word8 -> IO ()
foreign import ccall unsafe "GFp_x25519_sc_muladd"
  sc_muladd :: Ptr PackedBytes -> Ptr PackedBytes -> Ptr PackedBytes -> Ptr PackedBytes -> IO ()
foreign import ccall unsafe "GFp_x25519_public_from_private"
  public_from_private :: Ptr PackedBytes -> Ptr PackedBytes -> IO ()