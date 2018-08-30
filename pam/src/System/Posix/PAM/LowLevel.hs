{-# LANGUAGE ScopedTypeVariables #-}

module System.Posix.PAM.LowLevel where

import System.Posix.PAM.Types


import qualified System.Posix.PAM.MessageStyle as MessageStyle
import qualified System.Posix.PAM.Response as Response
import System.Posix.PAM.Response (Response)
import System.Posix.PAM.Result (Result (..))
import qualified System.Posix.PAM.Result as Result
import System.Posix.PAM.ErrorCode (ErrorCode (..))
import qualified System.Posix.PAM.ErrorCode as ErrorCode

-- base
import Data.Semigroup ((<>))
import Data.Traversable (traverse)
import Foreign.C (newCString, peekCString)
import Foreign.Marshal.Array (peekArray, mallocArray, pokeArray)
import Foreign.Marshal.Alloc (calloc, malloc, free)
import Foreign.Ptr (Ptr, castPtr, freeHaskellFunPtr)
import Foreign.Storable (peek, poke)

-- pam-bindings
import qualified System.Posix.PAM.Bindings as C

messageFromC :: C.PamMessage -> IO PamMessage
messageFromC cmes =
    PamMessage
        <$> peekCString (C.msg cmes)
        <*> MessageStyle.from_C_IO (C.msg_style cmes)

cConv :: (Ptr () -> [PamMessage] -> IO [Response]) -> C.ConvFunc
cConv customConv num mesArrPtr respArrPtr appData =
    if num <= 0
        then pure 19
        else do
            -- get array pointer (pointer to first element)
            voidArr <- peek mesArrPtr

            -- cast pointer type from ()
            let mesArr = castPtr voidArr :: Ptr C.PamMessage

            -- peek message list from array
            cMessages <- peekArray (fromIntegral num) mesArr

            -- convert messages into high-level types
            messages <- traverse messageFromC cMessages

            -- create response list
            responses <- customConv appData messages

            -- convert responses into low-level types
            cResponses <- traverse Response.to_C responses

            -- alloc memory for response array
            respArr <- mallocArray (fromIntegral num)

            -- poke resonse list into array
            pokeArray respArr cResponses

            -- poke array pointer into respArrPtr
            poke respArrPtr $ castPtr respArr

            -- return PAM_SUCCESS
            pure 0

pamStart :: String -> String -> (PamConv, Ptr ()) -> IO (PamHandle, Result ())
pamStart serviceName userName (pamConv, appData) = do
    cServiceName <- newCString serviceName
    cUserName <- newCString userName

    -- create FunPtr pointer to function and embedd PamConv function into cConv
    pamConvPtr <- C.mkconvFunc $ cConv pamConv

    let conv = C.Conv pamConvPtr appData

    convPtr <- malloc
    poke convPtr conv

    pamhPtr :: Ptr C.Handle <- calloc
    r1 :: C.ReturnValue <- C.pam_start cServiceName cUserName convPtr pamhPtr
    cPamHandle_ :: C.Handle <- peek pamhPtr

    free cServiceName
    free cUserName
    free convPtr
    free pamhPtr

    pure (PamHandle cPamHandle_ pamConvPtr, Result.from_C r1)

pamEnd :: PamHandle -> Result () -> IO (Result ())
pamEnd pamHandle inRetCode =
  do
    r <- C.pam_end (cPamHandle pamHandle) (Result.to_C inRetCode)
    freeHaskellFunPtr (cPamCallback pamHandle)

    return (Result.from_C r)

pamAuthenticate :: PamHandle -> PamFlag -> IO (Result ())
pamAuthenticate pamHandle (PamFlag flag) =
  do
    let cFlag = fromIntegral flag
    r <- C.pam_authenticate (cPamHandle pamHandle) cFlag
    return (Result.from_C r)

pamAcctMgmt :: PamHandle -> PamFlag -> IO (Result ())
pamAcctMgmt pamHandle (PamFlag flag) =
  do
    let cFlag = fromIntegral flag
    r <- C.pam_acct_mgmt (cPamHandle pamHandle) cFlag
    return (Result.from_C r)

pamErrorString :: PamHandle -> ErrorCode -> IO String
pamErrorString pamHandle errorCode =
  do
    cStr <- C.pam_strerror
              (cPamHandle pamHandle)
              (ErrorCode.to_C errorCode)
    peekCString cStr
