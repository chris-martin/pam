module System.Posix.PAM.Response
  ( Response (..)
  , to_C
  ) where

import qualified System.Posix.PAM.Bindings.Response as C

-- base
import Foreign.C (newCString)

{- | Used to return the user's response to the PAM library.

http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-of-app-expected.html#adg-pam_conv

The @resp_retcode@ member of the C struct is unused, so we do not bother
including a corresponding field in this Haskell type.

-}

data Response = Response String
  deriving (Show, Eq)

to_C :: Response -> IO C.Response
to_C (Response resp) =
    C.Response
        <$> newCString resp
        <*> pure 0
