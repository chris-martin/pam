{-# LANGUAGE FlexibleContexts #-}

module System.Posix.PAM.LowLevel where

import Control.Monad.Except
import Data.IORef
import Foreign.C
import Foreign.Marshal.Array
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import System.Posix.PAM.Types
import System.Posix.PAM.Internals hiding (resp, conv)

retCodeFromC :: CInt -> PamRetCode
retCodeFromC rc =
  PamRetCode (fromIntegral rc)

retCodeToC :: PamRetCode -> CInt
retCodeToC (PamRetCode a) = fromIntegral a

retCodeError :: PamRetCode -> Maybe PamErrorCode
retCodeError (PamRetCode 0) = Nothing
retCodeError (PamRetCode a) = Just (PamErrorCode a)

responseToC :: PamResponse -> IO CPamResponse
responseToC (PamResponse resp) = do
    resp' <- newCString resp
    return $ CPamResponse resp' 0

messageFromC :: CPamMessage -> IO PamMessage
messageFromC cmes =
    let style = case msg_style cmes of
            1 -> PamPromptEchoOff
            2 -> PamPromptEchoOn
            3 -> PamErrorMsg
            4 -> PamTextInfo
            a -> error $ "unknown style value: " ++ show a
    in do
        str <- peekCString $ msg cmes
        return $ PamMessage str style

cConv :: (Ptr () -> [PamMessage] -> IO [PamResponse]) -> CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt
cConv customConv num mesArrPtr respArrPtr appData =
    if num <= 0
        then return 19
        else do
            -- get array pointer (pointer to first element)
            voidArr <- peek mesArrPtr

            -- cast pointer type from ()
            let mesArr = castPtr voidArr :: Ptr CPamMessage

            -- peek message list from array
            cMessages <- peekArray (fromIntegral num) mesArr

            -- convert messages into high-level types
            messages <- mapM messageFromC cMessages

            -- create response list
            responses <- customConv appData messages

            -- convert responses into low-level types
            cResponses <- mapM responseToC responses

            -- alloc memory for response array
            respArr <- mallocArray (fromIntegral num)

            -- poke resonse list into array
            pokeArray respArr cResponses

            -- poke array pointer into respArrPtr
            poke respArrPtr $ castPtr respArr

            -- return PAM_SUCCESS
            return 0

pamStart :: (MonadIO m, MonadError PamErrorCode m)
  => String
  -> String
  -> (PamConv, Ptr ())
  -> m PamHandle
pamStart serviceName userName (pamConv, appData) = do
    cServiceName <- liftIO $ newCString serviceName
    cUserName <- liftIO $ newCString userName

    -- create FunPtr pointer to function and embedd PamConv function into cConv
    pamConvPtr <- liftIO $ mkconvFunc $ cConv pamConv

    let conv = CPamConv pamConvPtr appData

    convPtr <- liftIO $ malloc
    liftIO $ poke convPtr conv

    pamhPtr <- liftIO $ malloc
    liftIO $ poke pamhPtr nullPtr

    r1 <- liftIO $ c_pam_start cServiceName cUserName convPtr pamhPtr

    cPamHandle_ <- liftIO $ peek pamhPtr

    let retCode = case r1 of
            a -> PamRetCode $ fromIntegral a

    liftIO $ free cServiceName
    liftIO $ free cUserName
    liftIO $ free convPtr

    liftIO $ free pamhPtr

    case retCodeError retCode of
      Nothing ->
        PamHandle cPamHandle_ pamConvPtr <$> liftIO (newIORef retCode)
      Just e -> throwError e

pamEnd :: PamHandle -> PamRetCode -> IO PamRetCode
pamEnd pamHandle inRetCode = do
    let cRetCode = case inRetCode of
            PamRetCode a -> fromIntegral a
    r <- c_pam_end (cPamHandle pamHandle) cRetCode
    freeHaskellFunPtr $ cPamCallback pamHandle

    return $ retCodeFromC r

pamAuthenticate :: (MonadIO m, MonadError PamErrorCode m)
  => PamHandle -> PamFlag -> m ()
pamAuthenticate pamHandle (PamFlag flag) = do
  r <- liftIO $ retCodeFromC <$> c_pam_authenticate (cPamHandle pamHandle)
                                                    (fromIntegral flag)
  setLastRetCode pamHandle r
  case retCodeError r of
    Nothing -> return ()
    Just e -> throwError e

pamAcctMgmt :: (MonadIO m, MonadError PamErrorCode m)
  => PamHandle -> PamFlag -> m ()
pamAcctMgmt pamHandle (PamFlag flag) = do
  r <- liftIO $ retCodeFromC <$> c_pam_acct_mgmt (cPamHandle pamHandle)
                                                 (fromIntegral flag)
  setLastRetCode pamHandle r
  case retCodeError r of
    Nothing -> return ()
    Just e -> throwError e

setLastRetCode :: MonadIO m => PamHandle -> PamRetCode -> m ()
setLastRetCode pamHandle r =
  liftIO $ writeIORef (lastPamStatusRef pamHandle) r
