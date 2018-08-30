module System.Posix.PAM.MessageStyle
  (
  -- * Message style type
    MessageStyle (..)

  -- * Converting to/from C types
  , to_C
  , from_C_Maybe
  , from_C_IO

  ) where

import qualified System.Posix.PAM.Bindings.MessageStyle as C

-- base
import Foreign.C.Types (CInt)

data MessageStyle
  = PromptEchoOff
  | PromptEchoOn
  | ErrorMsg
  | TextInfo
  deriving (Show, Eq)

to_C :: MessageStyle -> C.MessageStyle
to_C PromptEchoOff  =  C.promptEchoOff
to_C PromptEchoOn   =  C.promptEchoOn
to_C ErrorMsg       =  C.errorMsg
to_C TextInfo       =  C.textInfo

from_C_Maybe :: C.MessageStyle -> Maybe MessageStyle
from_C_Maybe x | x == C.promptEchoOff  =  Just PromptEchoOff
from_C_Maybe x | x == C.promptEchoOn   =  Just PromptEchoOn
from_C_Maybe x | x == C.errorMsg       =  Just ErrorMsg
from_C_Maybe x | x == C.textInfo       =  Just TextInfo
from_C_Maybe _                         =  Nothing

from_C_IO :: C.MessageStyle -> IO MessageStyle
from_C_IO x@(C.MessageStyle i) =
  case (from_C_Maybe x) of
    Just s -> return s
    Nothing -> error ("Unknown MessageStyle: " <> show (i :: CInt))
