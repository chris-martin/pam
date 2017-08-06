{-# LANGUAGE DataKinds, DeriveAnyClass, DeriveGeneric, LambdaCase,
             NamedFieldPuns, OverloadedStrings, TypeOperators #-}

module Main (main) where

import qualified System.Posix.PAM as PAM

import Control.Monad.Trans.Maybe (MaybeT (..))
import Data.Bifunctor (Bifunctor (..))
import Data.Either (Either (..), either)
import Data.Function (($))
import Data.Functor (fmap, (<$>))
import Data.Maybe (Maybe (..), maybe)
import Data.Semigroup ((<>))
import Data.Text (Text)
import GHC.Generics (Generic)
import Options.Generic (type (<?>))
import Prelude (IO, Int, (<*>), (>>=), pure, putStrLn)
import System.Exit (exitFailure, die)
import Text.Show (show)

import qualified Data.Text as Text
import qualified Options.Applicative as Opt
import qualified Options.Generic as Opt (ParseRecord, parseRecord, unHelpful)
import qualified System.Console.Haskeline as Haskeline

--------------------------------------------------------------------------------

main :: IO ()
main =
  getArgs >>= \args ->
  getAuthReq args >>=
  maybe exitFailure authenticate >>=
  either
    (\e -> die (Text.unpack e))
    (\_ -> putStrLn "Authentication success")

--------------------------------------------------------------------------------

data Args = Args
  { service :: Maybe Text <?>
      "The name of the PAM service to use, e.g. \"login\" or \"system-auth\"."
  , username :: Maybe Text <?>
      "The name of the user you're authenticating."
  } deriving (Generic, Opt.ParseRecord)

getArgs :: IO Args
getArgs =
  Opt.execParser $
  Opt.info (Opt.helper <*> Opt.parseRecord) $
  Opt.header "Test whether a username/password is correct."

--------------------------------------------------------------------------------

data AuthReq = AuthReq
  { req'service :: Text
  , req'username :: Text
  , req'password :: Text
  }

getAuthReq :: Args -> IO (Maybe AuthReq)
getAuthReq args =
  runMaybeT $
  AuthReq <$>
  getService args <*>
  getUsername args <*>
  getPassword

getService :: Args -> MaybeT IO Text
getService Args{service} =
  maybe (prompt "Service: ") pure (Opt.unHelpful service)

getUsername :: Args -> MaybeT IO Text
getUsername Args{username} =
  maybe (prompt "Username: ") pure (Opt.unHelpful username)

getPassword :: MaybeT IO Text
getPassword =
  promptForPassword "Password: "

prompt :: Text -> MaybeT IO Text
prompt p =
  fmap Text.pack $ MaybeT $
  Haskeline.runInputT Haskeline.defaultSettings $
  Haskeline.getInputLine (Text.unpack p)

promptForPassword :: Text -> MaybeT IO Text
promptForPassword p =
  fmap Text.pack $ MaybeT $
  Haskeline.runInputT Haskeline.defaultSettings $
  Haskeline.getPassword Nothing (Text.unpack p)

--------------------------------------------------------------------------------

authenticate :: AuthReq -> IO (Either Text ())
authenticate AuthReq{req'service, req'username, req'password} =
  fmap
    (first renderError)
    (PAM.authenticate
      (Text.unpack req'service)
      (Text.unpack req'username)
      (Text.unpack req'password))

renderError :: (Int, Maybe Text) -> Text
renderError (code, maybeMessage) =
    maybe
      ("Error code " <> code')
      (\m -> m <> " (error code " <> code' <> ")")
      maybeMessage
  where
    code' = Text.pack $ show code
