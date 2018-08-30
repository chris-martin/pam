module System.Posix.PAM.CLI where

import qualified System.Posix.PAM as PAM

-- base
import Data.Maybe (maybe)
import Data.Semigroup ((<>))
import System.Exit (exitFailure)
import Numeric (showInt)

-- text
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT
import qualified Data.Text.Lazy.IO as LT
import qualified Data.Text.Lazy.Builder as TB

-- optparse-applicative
import qualified Options.Applicative as Opt

-- haskeline
import qualified System.Console.Haskeline as Haskeline

main :: IO ()
main =
  do
    (service, username) <- getOpts $
        (,)
        <$> textOpt "service"
                "The name of the PAM service to use, \
                \e.g. \"login\" or \"system-auth\"."
        <*> textOpt "username"
                "The name of the user you're authenticating."

    password <- promptForPassword >>= maybe exitFailure return

    result <- PAM.authenticate (PAM.AuthRequest service username password)
    case result of
        Left err -> LT.putStrLn (renderError err)
        Right () -> putStrLn "Authentication success"

textOpt :: String -> String -> Opt.Parser Text
textOpt long help = T.pack <$> Opt.strOption (Opt.long long <> Opt.help help)

progDesc :: String
progDesc = "Test whether a username/password is correct."

getOpts :: Opt.Parser a -> IO a
getOpts p = Opt.execParser (Opt.info p (Opt.progDesc progDesc))

promptForPassword :: IO (Maybe Text)
promptForPassword =
  do
    result <- Haskeline.runInputT Haskeline.defaultSettings
                  (Haskeline.getPassword Nothing "Password: ")
    return (T.pack <$> result)

renderError :: (PAM.ErrorCode, Maybe Text) -> LT.Text
renderError (code, maybeMessage) =
  let
      i = TB.fromString (showInt (PAM.errorCodeInt code) "")
  in
      TB.toLazyText $
          case maybeMessage of
              Nothing -> TB.fromString "Error code "
                      <> i
              Just m  -> TB.fromText m
                      <> TB.fromString " (error code "
                      <> i
                      <> TB.fromString ")"
