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
        <$> textOpt "The name of the PAM service to use, \
                    \e.g. \"login\" or \"system-auth\"."
        <*> textOpt "The name of the user you're authenticating."

    password <- promptForPassword >>= maybe exitFailure return

    result <- PAM.authenticate (PAM.AuthRequest service username password)
    case result of
        Left err -> LT.putStrLn (renderError err)
        Right () -> putStrLn "Authentication success"

textOpt :: String -> Opt.Parser Text
textOpt long = T.pack <$> Opt.strOption (Opt.long long)

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

renderError :: (Int, Maybe Text) -> LT.Text
renderError (code, maybeMessage) =
  TB.toLazyText $
      case maybeMessage of
          Nothing -> TB.fromString "Error code "
                  <> TB.fromString (showInt code "")
          Just m  -> TB.fromText m
                  <> TB.fromString " (error code "
                  <> TB.fromString (showInt code "")
                  <> TB.fromString ")"
