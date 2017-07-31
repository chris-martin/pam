module System.Posix.PAM.Types where

import Data.IORef
import Foreign.C
import Foreign.Ptr

{- |

Used to pass prompting text, error messages, or other informatory text to the
user.

-}
data PamMessage = PamMessage { pmString :: String
                             , pmStyle :: PamStyle
                             }
                             deriving (Show, Eq)

data PamStyle = PamPromptEchoOff
              | PamPromptEchoOn
              | PamErrorMsg
              | PamTextInfo
              deriving (Show, Eq)

{- |

Used to return the user's response to the PAM library.

http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-of-app-expected.html#adg-pam_conv

The @resp_retcode@ member of the C struct is unused, so we do not bother
including a corresponding field in this Haskell type.

 -}
data PamResponse = PamResponse String
                 deriving (Show, Eq)

newtype PamRetCode = PamRetCode Int
  deriving (Show, Eq)

newtype PamErrorCode = PamErrorCode Int
  deriving (Show, Eq)

data PamFlag = PamFlag Int

type PamConv = Ptr () -> [PamMessage] -> IO [PamResponse]

data PamHandle = PamHandle
  { cPamHandle :: Ptr ()
  , cPamCallback :: FunPtr (CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt)
  , lastPamStatusRef :: IORef PamRetCode
  }
