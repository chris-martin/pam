module System.Posix.PAM.Types where

import qualified System.Posix.PAM.Bindings as C

import System.Posix.PAM.MessageStyle (MessageStyle)
import System.Posix.PAM.Response (Response)

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

data PamRetCode = PamSuccess | PamRetCode Int
  deriving (Show, Eq)

data PamFlag = PamFlag Int

type PamConv = Ptr () -> [PamMessage] -> IO [Response]

data PamHandle =
  PamHandle
    { cPamHandle :: C.Handle
    , cPamCallback :: FunPtr C.ConvFunc
    }

data AuthRequest =
  AuthRequest
    { authRequestService :: Text
    , authRequestUsername :: Text
    , authRequestPassword :: Text
    }
  deriving (Show, Eq)
