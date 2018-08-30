module System.Posix.PAM.ErrorCode where

import System.Posix.PAM.ReturnValue
import qualified System.Posix.PAM.ReturnValue as ReturnValue

-- pam-bindings
import qualified System.Posix.PAM.Bindings.ReturnValue as C

newtype ErrorCode = ErrorCode ReturnValue
  deriving (Show, Eq)

to_C :: ErrorCode -> C.ReturnValue
to_C (ErrorCode x) = ReturnValue.to_C x

from_C :: C.ReturnValue -> ErrorCode
from_C x = ErrorCode (ReturnValue.from_C x)

to_Int :: ErrorCode -> Int
to_Int (ErrorCode x) = ReturnValue.to_Int x
