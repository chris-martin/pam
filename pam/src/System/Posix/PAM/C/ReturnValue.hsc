{-# LANGUAGE ForeignFunctionInterface #-}

module System.Posix.PAM.C.ReturnValue where

import Foreign.C (CInt (..))

#include <security/pam_appl.h>

newtype PamReturnValue = PamReturnValue CInt

#{enum PamReturnValue, PamReturnValue
  , success = PAM_SUCCESS
  , open_err = PAM_OPEN_ERR
  }
