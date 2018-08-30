{-# LANGUAGE ScopedTypeVariables #-}

module System.Posix.PAM.LowLevel where

import System.Posix.PAM.Types

import qualified System.Posix.PAM.Bindings as C

import Data.Semigroup ((<>))
import Data.Traversable (traverse)
import Foreign.C (newCString, peekCString)
import Foreign.Marshal.Array (peekArray, mallocArray, pokeArray)
import Foreign.Marshal.Alloc (calloc, malloc, free)
import Foreign.Ptr (Ptr, castPtr, freeHaskellFunPtr)
import Foreign.Storable (peek, poke)

retCodeFromC :: C.ReturnValue -> PamRetCode
retCodeFromC r | r == C.success  =  PamSuccess
retCodeFromC (C.ReturnValue x)   =  PamRetCode (fromIntegral x)

retCodeToC :: PamRetCode -> C.ReturnValue
retCodeToC PamSuccess      =  C.success
retCodeToC (PamRetCode x)  =  C.ReturnValue (fromIntegral x)

responseToC :: PamResponse -> IO C.PamResponse
responseToC (PamResponse resp) = do
    resp' <- newCString resp
    pure $ C.PamResponse resp' 0

messageFromC :: C.PamMessage -> IO PamMessage
messageFromC cmes =
    let style = case C.msg_style cmes of
            1 -> PamPromptEchoOff
            2 -> PamPromptEchoOn
            3 -> PamErrorMsg
            4 -> PamTextInfo
            a -> error $ "unknown style value: " <> show a
    in do
        str <- peekCString $ C.msg cmes
        pure $ PamMessage str style

cConv :: (Ptr () -> [PamMessage] -> IO [PamResponse]) -> C.ConvFunc
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
            cResponses <- traverse responseToC responses

            -- alloc memory for response array
            respArr <- mallocArray (fromIntegral num)

            -- poke resonse list into array
            pokeArray respArr cResponses

            -- poke array pointer into respArrPtr
            poke respArrPtr $ castPtr respArr

            -- return PAM_SUCCESS
            pure 0

pamStart :: String -> String -> (PamConv, Ptr ()) -> IO (PamHandle, PamRetCode)
pamStart serviceName userName (pamConv, appData) = do
    cServiceName <- newCString serviceName
    cUserName <- newCString userName

    -- create FunPtr pointer to function and embedd PamConv function into cConv
    pamConvPtr <- C.mkconvFunc $ cConv pamConv

    let conv = C.PamConv pamConvPtr appData

    convPtr <- malloc
    poke convPtr conv

    pamhPtr :: Ptr C.PamHandle <- calloc
    r1 :: C.ReturnValue <- C.pam_start cServiceName cUserName convPtr pamhPtr
    cPamHandle_ :: C.PamHandle <- peek pamhPtr

    free cServiceName
    free cUserName
    free convPtr
    free pamhPtr

    pure (PamHandle cPamHandle_ pamConvPtr, retCodeFromC r1)

pamEnd :: PamHandle -> PamRetCode -> IO PamRetCode
pamEnd pamHandle inRetCode = do
    let cRetCode = case inRetCode of
            PamSuccess -> 0
            PamRetCode a -> fromIntegral a
    r <- C.pam_end (cPamHandle pamHandle) cRetCode
    freeHaskellFunPtr $ cPamCallback pamHandle

    pure $ retCodeFromC r

pamAuthenticate :: PamHandle -> PamFlag -> IO PamRetCode
pamAuthenticate pamHandle (PamFlag flag) = do
    let cFlag = fromIntegral flag
    r <- C.pam_authenticate (cPamHandle pamHandle) cFlag
    pure $ retCodeFromC r

pamAcctMgmt :: PamHandle -> PamFlag -> IO PamRetCode
pamAcctMgmt pamHandle (PamFlag flag) = do
    let cFlag = fromIntegral flag
    r <- C.pam_acct_mgmt (cPamHandle pamHandle) cFlag
    pure $ retCodeFromC r

pamErrorString :: PamHandle -> Int -> IO String
pamErrorString pamHandle errorCode =
  do
    cStr <- C.pam_strerror
              (cPamHandle pamHandle)
              (C.ReturnValue (fromIntegral errorCode))
    peekCString cStr
