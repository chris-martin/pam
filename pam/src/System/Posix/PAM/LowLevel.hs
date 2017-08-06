module System.Posix.PAM.LowLevel where

import Control.Applicative (pure)
import Control.Monad ((>>=))
import Data.Function (($))
import Data.Ord (Ord (..))
import Data.Semigroup ((<>))
import Data.Traversable (traverse)
import Foreign.C
import Foreign.Marshal.Array
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import Prelude (Int, String, fromIntegral, error)
import System.IO (IO)
import System.Posix.PAM.Types
import System.Posix.PAM.Internals hiding (resp, conv)
import Text.Show (show)

retCodeFromC :: CInt -> PamRetCode
retCodeFromC rc = case rc of
            0 -> PamSuccess
            a -> PamRetCode $ fromIntegral a

retCodeToC :: PamRetCode -> CInt
retCodeToC PamSuccess = 0
retCodeToC (PamRetCode a) = fromIntegral a

responseToC :: PamResponse -> IO CPamResponse
responseToC (PamResponse resp) = do
    resp' <- newCString resp
    pure $ CPamResponse resp' 0

messageFromC :: CPamMessage -> IO PamMessage
messageFromC cmes =
    let style = case msg_style cmes of
            1 -> PamPromptEchoOff
            2 -> PamPromptEchoOn
            3 -> PamErrorMsg
            4 -> PamTextInfo
            a -> error $ "unknown style value: " <> show a
    in do
        str <- peekCString $ msg cmes
        pure $ PamMessage str style

cConv :: (Ptr () -> [PamMessage] -> IO [PamResponse]) -> ConvFunc
cConv customConv num mesArrPtr respArrPtr appData =
    if num <= 0
        then pure 19
        else do
            -- get array pointer (pointer to first element)
            voidArr <- peek mesArrPtr

            -- cast pointer type from ()
            let mesArr = castPtr voidArr :: Ptr CPamMessage

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
    pamConvPtr <- mkconvFunc $ cConv pamConv

    let conv = CPamConv pamConvPtr appData

    convPtr <- malloc
    poke convPtr conv

    pamhPtr <- malloc
    poke pamhPtr nullPtr

    r1 <- c_pam_start cServiceName cUserName convPtr pamhPtr

    cPamHandle_ <- peek pamhPtr

    let retCode = case r1 of
            0 -> PamSuccess
            a -> PamRetCode $ fromIntegral a

    free cServiceName
    free cUserName
    free convPtr

    free pamhPtr

    pure (PamHandle cPamHandle_ pamConvPtr, retCode)

pamEnd :: PamHandle -> PamRetCode -> IO PamRetCode
pamEnd pamHandle inRetCode = do
    let cRetCode = case inRetCode of
            PamSuccess -> 0
            PamRetCode a -> fromIntegral a
    r <- c_pam_end (cPamHandle pamHandle) cRetCode
    freeHaskellFunPtr $ cPamCallback pamHandle

    pure $ retCodeFromC r

pamAuthenticate :: PamHandle -> PamFlag -> IO PamRetCode
pamAuthenticate pamHandle (PamFlag flag) = do
    let cFlag = fromIntegral flag
    r <- c_pam_authenticate (cPamHandle pamHandle) cFlag
    pure $ retCodeFromC r

pamAcctMgmt :: PamHandle -> PamFlag -> IO PamRetCode
pamAcctMgmt pamHandle (PamFlag flag) = do
    let cFlag = fromIntegral flag
    r <- c_pam_acct_mgmt (cPamHandle pamHandle) cFlag
    pure $ retCodeFromC r

pamErrorString :: PamHandle -> Int -> IO String
pamErrorString pamHandle errorCode =
    c_pam_strerror (cPamHandle pamHandle) (fromIntegral errorCode) >>=
    peekCString
