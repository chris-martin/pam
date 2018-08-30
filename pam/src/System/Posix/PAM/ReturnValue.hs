module System.Posix.PAM.ReturnValue where

-- pam-bindings
import qualified System.Posix.PAM.Bindings.ReturnValue as C

newtype ReturnValue = ReturnValue Int
  deriving (Show, Eq)

to_C :: ReturnValue -> C.ReturnValue
to_C (ReturnValue x) = C.ReturnValue (fromIntegral x)

from_C :: C.ReturnValue -> ReturnValue
from_C (C.ReturnValue x) = ReturnValue (fromIntegral x)

to_Int :: ReturnValue -> Int
to_Int (ReturnValue i) = i
