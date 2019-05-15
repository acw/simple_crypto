{-# LANGUAGE PackageImports #-}
module ECDSATesting(
          ecdsaTasks
       )
 where

import Crypto.Hash(SHA224(..),SHA256(..),SHA384(..),SHA512(..))
import Crypto.Number.Generate(generateBetween)
import Crypto.PubKey.ECC.ECDSA(PrivateKey(..),PublicKey(..),Signature(..),signWith)
import Crypto.PubKey.ECC.Generate(generate)
import Crypto.PubKey.ECC.Prim(scalarGenerate,pointAdd,pointNegate,pointDouble,pointBaseMul,pointMul,pointAddTwoMuls)
import Crypto.PubKey.ECC.Types(Curve,CurveName(..),Point(..),common_curve,curveSizeBits,ecc_n,getCurveByName)
import "cryptonite" Crypto.Random(DRG(..),getRandomBytes,withDRG)
import qualified Data.ByteString as S
import qualified Data.Map.Strict as Map
import Math(showX,showBin)
import RFC6979(generateKStream)
import Task(Task(..),liftTest)
import Utils(HashAlg(..),generateHash,runHash,showHash)

curves :: [(String, Curve)]
curves = [("P192", getCurveByName SEC_p192r1),
          ("P224", getCurveByName SEC_p224r1),
          ("P256", getCurveByName SEC_p256r1),
          ("P384", getCurveByName SEC_p384r1),
          ("P521", getCurveByName SEC_p521r1)]

negateTest :: String -> Curve -> Task
negateTest name curve = Task {
    taskName = name ++ " point negation",
    taskFile = "../testdata/ecc/negate/" ++ name ++ ".test",
    taskTest = liftTest go,
    taskCount = 1000
}
 where
  go (memory0, drg) =
    let (scalar, drg') = withDRG drg (scalarGenerate curve)
        point = pointBaseMul curve scalar
        dbl = pointNegate curve point
    in case (point, dbl) of
         (PointO, _) -> go (memory0, drg')
         (_, PointO) -> go (memory0, drg')
         (Point basex basey, Point dblx dbly) ->
            let res = Map.fromList [("x", showX basex), ("y", showX basey),
                                    ("a", showX dblx),  ("b", showX dbly)]
            in (res, scalar, (memory0, drg'))

doubleTest :: String -> Curve -> Task
doubleTest name curve = Task {
    taskName = name ++ " point doubling",
    taskFile = "../testdata/ecc/double/" ++ name ++ ".test",
    taskTest = liftTest go,
    taskCount = 1000
}
 where
  go (memory0, drg) =
    let (scalar, drg') = withDRG drg (scalarGenerate curve)
        point = pointBaseMul curve scalar
        dbl = pointDouble curve point
    in case (point, dbl) of
         (PointO, _) -> go (memory0, drg')
         (_, PointO) -> go (memory0, drg')
         (Point basex basey, Point dblx dbly) ->
            let res = Map.fromList [("x", showX basex), ("y", showX basey),
                                    ("a", showX dblx),  ("b", showX dbly)]
            in (res, scalar, (memory0, drg'))

addTest :: String -> Curve -> Task
addTest name curve = Task {
    taskName = name ++ " point addition",
    taskFile = "../testdata/ecc/add/" ++ name ++ ".test",
    taskTest = liftTest go,
    taskCount = 1000
}
 where
  go (memory0, drg0) =
    let (scalar1, drg1) = withDRG drg0 (scalarGenerate curve)
        (scalar2, drg2) = withDRG drg1 (scalarGenerate curve)
        point1 = pointBaseMul curve scalar1
        point2 = pointBaseMul curve scalar2
        pointr = pointAdd curve point1 point2
    in case (point1, point2, pointr) of
         (Point x1 y1, Point x2 y2, Point xr yr) ->
            let res = Map.fromList [("x", showX x1), ("y", showX y1),
                                    ("u", showX x2), ("v", showX y2),
                                    ("a", showX xr), ("b", showX yr)]
            in (res, scalar1, (memory0, drg2))
         _ ->
            go (memory0, drg2)

scaleTest :: String -> Curve -> Task
scaleTest name curve = Task {
    taskName = name ++ " point scaling",
    taskFile = "../testdata/ecc/scale/" ++ name ++ ".test",
    taskTest = liftTest go,
    taskCount = 1000
}
 where
  go (memory0, drg0) =
    let (scalar0, drg1) = withDRG drg0 (scalarGenerate curve)
        (scalar1, drg2) = withDRG drg1 (scalarGenerate curve)
        (negbs,   drg3) = randomBytesGenerate 1 drg2
        [negbyte]       = S.unpack negbs
        k               = if odd negbyte then scalar1 else -scalar1 
        point           = pointBaseMul curve scalar0
        respnt          = pointMul curve k point
    in case (point, respnt) of
         (PointO, _) -> go (memory0, drg3)
         (_, PointO) -> go (memory0, drg3)
         (Point basex basey, Point resx resy) ->
            let res = Map.fromList [("x", showX basex), ("y", showX basey),
                                    ("k", showX k),
                                    ("a", showX resx),  ("b", showX resy)]
            in (res, scalar0, (memory0, drg3))

addScaleTest :: String -> Curve -> Task
addScaleTest name curve = Task {
    taskName = name ++ " point addition of two scalings",
    taskFile = "../testdata/ecc/add_scale2/" ++ name ++ ".test",
    taskTest = liftTest go,
    taskCount = 1000
}
 where
  go (memory0, drg0) =
    let (scalar1, drg1) = withDRG drg0 (scalarGenerate curve)
        (scalar2, drg2) = withDRG drg1 (scalarGenerate curve)
        (n,       drg3) = withDRG drg2 (scalarGenerate curve)
        (m,       drg4) = withDRG drg3 (scalarGenerate curve)
        point1 = pointBaseMul curve scalar1
        point2 = pointBaseMul curve scalar2
        pointr = pointAddTwoMuls curve n point1 m point2
    in case (point1, point2, pointr) of
         (Point x1 y1, Point x2 y2, Point xr yr) ->
            let res = Map.fromList [("x", showX x1), ("y", showX y1),
                                    ("p", showX x2), ("q", showX y2),
                                    ("n", showX n),  ("m", showX m),
                                    ("r", showX xr), ("s", showX yr)]
            in (res, scalar1, (memory0, drg4))
         _ ->
            go (memory0, drg4)


signTest :: String -> Curve -> Task
signTest name curve = Task {
    taskName = name ++ " curve signing",
    taskFile = "../testdata/ecc/sign/" ++ name ++ ".test",
    taskTest = liftTest go,
    taskCount = 1000
}
 where
  go (memory0, drg0) =
    let ((pub, priv), drg1) = withDRG drg0 (generate curve)
        (msg, drg2)         = withDRG drg1 $ do x <- generateBetween 0 256
                                                getRandomBytes (fromIntegral x)
        (hash, drg3)        = withDRG drg2 generateHash
        n                   = ecc_n (common_curve curve)
        PrivateKey _ d      = priv
        kStream             = generateKStream hash msg d n (curveSizeBits curve)
        findGoodK stream    =
          case stream of
            [] ->
              go (memory0, drg3)
            (k : restks) ->
              case signWith' k priv hash msg of
                Nothing ->
                  findGoodK restks
                Just sig ->
                  let PublicKey _ (Point x y) = pub
                      res = Map.fromList [("d", showX d), ("k", showX k),
                                          ("x", showX x), ("y", showX y),
                                          ("m", showBin msg), ("h", showHash hash),
                                          ("n", showBin (runHash hash msg)),
                                          ("r", showX (sign_r sig)),
                                          ("s", showX (sign_s sig))]
                  in (res, d, (memory0, drg3))
    in findGoodK kStream

signWith' :: Integer -> PrivateKey -> HashAlg -> S.ByteString -> Maybe Signature
signWith' k priv Sha224 msg = signWith k priv SHA224 msg
signWith' k priv Sha256 msg = signWith k priv SHA256 msg
signWith' k priv Sha384 msg = signWith k priv SHA384 msg
signWith' k priv Sha512 msg = signWith k priv SHA512 msg

generateTasks :: (String, Curve) -> [Task]
generateTasks (name, curve) = [negateTest name curve,
                               doubleTest name curve,
                               addTest name curve,
                               scaleTest name curve,
                               addScaleTest name curve,
                               signTest name curve] 

ecdsaTasks :: [Task]
ecdsaTasks = concatMap generateTasks curves