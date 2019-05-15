{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE PackageImports #-}
import Control.Concurrent(forkIO)
import Control.Concurrent.Chan(Chan,newChan,readChan,writeChan)
import Control.Concurrent.MVar(MVar,newMVar,modifyMVar)
import Control.Exception(SomeException,catch)
import Control.Monad(replicateM_,void)
import "crypto-api" Crypto.Random(CryptoRandomGen(..),SystemRandom)
import DSA(dsaTasks)
import ECDSATesting(ecdsaTasks)
import ED25519(ed25519Tasks)
import GHC.Conc(getNumCapabilities)
import RFC6979(rfcTasks)
import RSA(rsaTasks)
import System.Console.AsciiProgress
import Task(Task, runTask)

taskExecutor :: MVar [Task] -> Chan () -> SystemRandom -> IO SystemRandom
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
  do gen <- newGenIO
     void (forkIO (catch (void (taskExecutor tasks done gen)) handler))
 where
  handler :: SomeException -> IO ()
  handler e = putStrLn ("ERROR: " ++ show e)

main :: IO ()
main = displayConsoleRegions $
    do 
       executors <- getNumCapabilities
       done <- newChan
       tasks <- newMVar (dsaTasks ++ ecdsaTasks ++ rfcTasks ++ rsaTasks ++ ed25519Tasks)
       replicateM_ executors (spawnExecutor tasks done)
       replicateM_ executors (void $ readChan done)