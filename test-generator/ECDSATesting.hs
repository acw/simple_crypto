module ECDSATesting(
          ecdsaTasks
       )
 where

import Crypto.PubKey.ECC.Prim(scalarGenerate,pointAdd,pointNegate,pointDouble,pointBaseMul,pointMul)
import Crypto.PubKey.ECC.Types(Curve,CurveName(..),Point(..),getCurveByName)
import Crypto.Random(withDRG)
import qualified Data.Map.Strict as Map
import Math(showX)
import Task(Task(..))

curves :: [(String, Curve)]
curves = [("P192", getCurveByName SEC_p192r1)]

negateTest :: String -> Curve -> Task
negateTest name curve = Task {
    taskName = name ++ " point negation",
    taskFile = "../testdata/ecc/negate/" ++ name ++ ".test",
    taskTest = go,
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
    taskTest = go,
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
    taskTest = go,
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
    taskTest = go,
    taskCount = 1000
}
 where
  go (memory0, drg0) =
    let (scalar0, drg1) = withDRG drg0 (scalarGenerate curve)
        (scalar1, drg2) = withDRG drg1 (scalarGenerate curve)
        point = pointBaseMul curve scalar0
        respnt = pointMul curve scalar1 point
    in case (point, respnt) of
         (PointO, _) -> go (memory0, drg2)
         (_, PointO) -> go (memory0, drg2)
         (Point basex basey, Point resx resy) ->
            let res = Map.fromList [("x", showX basex), ("y", showX basey),
                                    ("k", showX scalar1),
                                    ("a", showX resx),  ("b", showX resy)]
            in (res, scalar0, (memory0, drg2))

generateTasks :: (String, Curve) -> [Task]
generateTasks (name, curve) = [negateTest name curve,
                               doubleTest name curve,
                               addTest name curve,
                               scaleTest name curve] 

ecdsaTasks :: [Task]
ecdsaTasks = concatMap generateTasks curves