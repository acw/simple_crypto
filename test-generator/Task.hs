{-# LANGUAGE PackageImports #-}
module Task(
         Test,
         Task(..),
         runTask
       )
 where

import              Control.Monad(foldM, forM_)
import "crypto-api" Crypto.Random(SystemRandom)
import qualified    Data.Map.Strict as Map
import              Database
import              System.Console.AsciiProgress
import              System.Directory(createDirectoryIfMissing,doesFileExist)
import              System.FilePath(takeDirectory)
import              System.IO(Handle,IOMode(..),hPutStrLn,withFile)

type Test = Database -> (Map.Map String String, Integer, Database)

data Task = Task {
    taskName  :: String,
    taskFile  :: FilePath,
    taskTest  :: Test,
    taskCount :: Int
}

runTask :: SystemRandom -> Task -> IO SystemRandom
runTask gen task =
  do createDirectoryIfMissing True (takeDirectory (taskFile task))
     alreadyDone <- doesFileExist (taskFile task)
     if alreadyDone
        then return gen
        else withFile (taskFile task) WriteMode $ \ hndl ->
               do pg <- newProgressBar def{ pgOnCompletion = Just ("Finished " ++ taskName task),
                                            pgFormat = taskName task ++ " " ++ pgFormat def,
                                            pgTotal = fromIntegral (taskCount task) }
                  let initval = emptyDatabase gen
                  (_, gen') <- foldM (writer hndl pg (taskTest task)) initval [0..taskCount task]
                  return gen'
 where
  writer :: Handle -> ProgressBar -> Test -> Database -> Int -> IO Database
  writer hndl pg runner db x =
    do let (output, key, acc@(db',gen')) = runner db
           before = Map.findWithDefault [] "RESULT" db'
       if length (filter (== key) before) >= 10
          then writer hndl pg runner acc x
          else do forM_ (Map.toList output) $ \ (outkey, val) ->
                    hPutStrLn hndl (outkey ++ ": " ++ val)
                  tick pg
                  return (Map.insert "RESULT" (key : before) db', gen')

