module System.Posix.PAM.Types where

import System.Posix.PAM.Internals (ConvFunc)

import Data.Eq (Eq)
import Foreign.Ptr
import Prelude (Int, String)
import System.IO (IO)
import Text.Show (Show)

{- | Used to pass prompting text, error messages, or other informatory text to
the user. -}
data PamMessage =
  PamMessage
    { pmString :: String
    , pmStyle :: PamStyle
    }
  deriving (Show, Eq)

data PamStyle =
  PamPromptEchoOff | PamPromptEchoOn | PamErrorMsg | PamTextInfo
  deriving (Show, Eq)

{- | Used to return the user's response to the PAM library.

http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-of-app-expected.html#adg-pam_conv

The @resp_retcode@ member of the C struct is unused, so we do not bother
including a corresponding field in this Haskell type. -}
data PamResponse = PamResponse String
  deriving (Show, Eq)

data PamRetCode = PamSuccess | PamRetCode Int
  deriving (Show, Eq)

data PamFlag = PamFlag Int

type PamConv = Ptr () -> [PamMessage] -> IO [PamResponse]

data PamHandle =
  PamHandle
    { cPamHandle :: Ptr ()
    , cPamCallback :: FunPtr ConvFunc
    }
  deriving (Show, Eq)
