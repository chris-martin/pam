{-# LANGUAGE CPP, GeneralizedNewtypeDeriving, RecordWildCards #-}

module System.Posix.PAM.Bindings.Types
  ( PamMessage (..)
  ) where

import System.Posix.PAM.Bindings.Handle (Handle (..))
import System.Posix.PAM.Bindings.MessageStyle (MessageStyle (..))

import Foreign.C (CInt, CString)
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.Storable (Storable (..))

#include <security/pam_appl.h>

{- |

Used to pass prompting text, error messages, or other informatory text to the
user.

This structure is allocated and freed by the PAM library (or loaded module).

-}

data PamMessage = PamMessage
  { msg_style :: MessageStyle
  , msg :: CString
  }

instance Storable PamMessage where

  sizeOf    _ = #size      struct pam_message
  alignment _ = #alignment struct pam_message

  peek ptr = do
    msg_style <- #{peek struct pam_message, msg_style} ptr
    msg       <- #{peek struct pam_message, msg}       ptr
    return PamMessage{..}

  poke ptr PamMessage{..} = do
    #{poke struct pam_message, msg_style} ptr msg_style
    #{poke struct pam_message, msg}       ptr msg
