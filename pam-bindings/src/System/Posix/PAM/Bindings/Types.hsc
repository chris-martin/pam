{-# LANGUAGE CPP, GeneralizedNewtypeDeriving, RecordWildCards #-}

module System.Posix.PAM.Bindings.Types
  ( PamMessage (..)
  , ConvFunc
  , PamConv (..)
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

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt

{- |

The actual conversation structure itself.

-}

data PamConv = PamConv
  { conv :: FunPtr ConvFunc
  , appdata_ptr :: Ptr ()
  }
  deriving (Eq, Show)

instance Storable PamConv where

  sizeOf    _ = #size      struct pam_conv
  alignment _ = #alignment struct pam_conv

  peek ptr = do
    conv        <- #{peek struct pam_conv, conv}        ptr
    appdata_ptr <- #{peek struct pam_conv, appdata_ptr} ptr
    return PamConv{..}

  poke ptr PamConv{..} = do
    #{poke struct pam_conv, conv}        ptr conv
    #{poke struct pam_conv, appdata_ptr} ptr appdata_ptr
