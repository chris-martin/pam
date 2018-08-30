module System.Posix.PAM.Types where

import qualified System.Posix.PAM.Bindings as C

import System.Posix.PAM.MessageStyle (MessageStyle)

import Data.Eq (Eq)
import Data.Text (Text)
import Foreign.Ptr
import Prelude (Int, String)
import System.IO (IO)
import Text.Show (Show)

{- |

Used to pass prompting text, error messages, or other informatory text to the
user.

-}

data PamMessage =
  PamMessage
    { pmString :: String
    , pmStyle :: MessageStyle
    }
  deriving (Show, Eq)

{- | Used to return the user's response to the PAM library.

http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-of-app-expected.html#adg-pam_conv

The @resp_retcode@ member of the C struct is unused, so we do not bother
including a corresponding field in this Haskell type.

-}

data PamResponse = PamResponse String
  deriving (Show, Eq)

data PamRetCode = PamSuccess | PamRetCode Int
  deriving (Show, Eq)

data PamFlag = PamFlag Int

type PamConv = Ptr () -> [PamMessage] -> IO [PamResponse]

data PamHandle =
  PamHandle
    { cPamHandle :: C.PamHandle
    , cPamCallback :: FunPtr C.ConvFunc
    }

data AuthRequest =
  AuthRequest
    { authRequestService :: Text
    , authRequestUsername :: Text
    , authRequestPassword :: Text
    }
  deriving (Show, Eq)
