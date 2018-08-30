{- |

http://www.linux-pam.org/

http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html

-}

{-# LANGUAGE NamedFieldPuns, OverloadedStrings #-}

module System.Posix.PAM
  (
  -- * Authenticate
    authenticate
  , AuthRequest (..)

  -- * Errors
  , ErrorCode
  , errorCodeInt

  ) where

import System.Posix.PAM.ErrorCode
import qualified System.Posix.PAM.ErrorCode as ErrorCode
import System.Posix.PAM.LowLevel
import System.Posix.PAM.Response
import System.Posix.PAM.Result
import System.Posix.PAM.Types

-- base
import Foreign.Ptr

-- text
import Data.Text (Text)
import qualified Data.Text as Text

errorCodeInt :: ErrorCode -> Int
errorCodeInt = ErrorCode.to_Int

authenticate
  :: AuthRequest
  -> IO (Either (ErrorCode, Maybe Text) ())
authenticate AuthRequest{ authRequestService
                        , authRequestUsername
                        , authRequestPassword
                        } =
  do
    let custConv :: String -> PamConv
        custConv pass _ messages =
            pure $ fmap (\_ -> Response pass) messages
    (pamH, r1) <- pamStart
        (Text.unpack authRequestService)
        (Text.unpack authRequestUsername)
        (custConv (Text.unpack authRequestPassword), nullPtr)
    case r1 of
        Failure code -> pure $ Left (code, Nothing)
        Success () -> do
            r2 <- pamAuthenticate pamH (PamFlag 0)
            case r2 of
                Failure code -> do
                    errorMessage <- pamErrorString pamH code
                    pure $ Left (code, Just $ Text.pack errorMessage)
                Success () -> do
                    r3 <- pamEnd pamH r2
                    case r3 of
                        Failure code -> pure $ Left (code, Nothing)
                        Success () -> pure $ Right ()
