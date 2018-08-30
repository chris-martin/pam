{-# LANGUAGE DeriveFunctor #-}

module System.Posix.PAM.Result where

import System.Posix.PAM.ErrorCode
import qualified System.Posix.PAM.ErrorCode as ErrorCode

-- pam-bindings
import qualified System.Posix.PAM.Bindings.ReturnValue as C

data Result a
  = Success a
  | Failure ErrorCode
  deriving (Functor, Show, Eq)

to_C :: Result () -> C.ReturnValue
to_C (Success ())  =  C.success
to_C (Failure x)   =  ErrorCode.to_C x

from_C :: C.ReturnValue -> Result ()
from_C x | x == C.success  =  Success ()
from_C x                   =  Failure (ErrorCode.from_C x)
