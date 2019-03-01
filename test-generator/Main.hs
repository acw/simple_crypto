{-# LANGUAGE LambdaCase #-}
import Control.Concurrent(forkIO)
import Control.Concurrent.Chan(Chan,newChan,readChan,writeChan)
import Control.Concurrent.MVar(MVar,newMVar,modifyMVar)
import Control.Exception(SomeException,catch)
import Control.Monad(replicateM_,void)
import Crypto.Random(SystemDRG,getSystemDRG)
import ECDSATesting(ecdsaTasks)
import GHC.Conc(getNumCapabilities)
import RFC6979(rfcTasks)
import System.Console.AsciiProgress
import Task(Task, runTask)

taskExecutor :: MVar [Task] -> Chan () -> SystemDRG -> IO SystemDRG
taskExecutor taskList done gen =
    do mnext <- modifyMVar taskList (\case
                                       [] -> return ([], Nothing)
                                       (x:xs) -> return (xs, Just x))
       case mnext of
         Nothing -> do writeChan done ()
                       return gen
         Just x  -> do gen' <- runTask gen x
                       taskExecutor taskList done gen'

spawnExecutor :: MVar [Task] -> Chan () -> IO ()
spawnExecutor tasks done =
  do gen <- getSystemDRG
     void (forkIO (catch (void (taskExecutor tasks done gen)) handler))
 where
  handler :: SomeException -> IO ()
  handler e = putStrLn ("ERROR: " ++ show e)

main :: IO ()
main = displayConsoleRegions $
    do 
       executors <- getNumCapabilities
       done <- newChan
       tasks <- newMVar (ecdsaTasks ++ rfcTasks)
       replicateM_ executors (spawnExecutor tasks done)
       replicateM_ executors (void $ readChan done)