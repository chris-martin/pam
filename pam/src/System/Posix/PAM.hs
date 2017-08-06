{- |

http://www.linux-pam.org/

http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html

-}

{-# LANGUAGE OverloadedStrings #-}

module System.Posix.PAM where

import System.Posix.PAM.LowLevel
import System.Posix.PAM.Types

import Control.Applicative (pure)
import Data.Either (Either (..))
import Data.Function (($))
import Data.Functor (fmap)
import Data.Maybe (Maybe (..))
import Data.Text (Text)
import Foreign.Ptr
import Prelude (Int, String)
import System.IO (IO)

import qualified Data.Text as Text

authenticate
  :: String -- ^ Service name
  -> String -- ^ User name
  -> String -- ^ Password
  -> IO (Either (Int, Maybe Text) ())
authenticate serviceName userName password = do
    let custConv :: String -> PamConv
        custConv pass _ messages =
            pure $ fmap (\_ -> PamResponse pass) messages
    (pamH, r1) <- pamStart serviceName userName (custConv password, nullPtr)
    case r1 of
        PamRetCode code -> pure $ Left (code, Nothing)
        PamSuccess -> do
            r2 <- pamAuthenticate pamH (PamFlag 0)
            case r2 of
                PamRetCode code -> do
                    errorMessage <- pamErrorString pamH code
                    pure $ Left (code, Just $ Text.pack errorMessage)
                PamSuccess -> do
                    r3 <- pamEnd pamH r2
                    case r3 of
                        PamSuccess -> pure $ Right ()
                        PamRetCode code -> pure $ Left (code, Nothing)
