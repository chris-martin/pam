{-# LANGUAGE CPP, RecordWildCards #-}

module System.Posix.PAM.Bindings.Types
  ( PamHandle (..)
  , PamMessage (..)
  , PamResponse (..)
  , ConvFunc
  , PamConv (..)
  ) where

import Data.Void (Void)
import Foreign.C (CInt, CString)
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.Storable (Storable (..))

#include <security/pam_appl.h>

{- |

An opaque handle to a PAM session, obtained using 'pam_start' and freed using
'pam_end'.

You must use a different 'PamHandle' for each transaction.

-}

newtype PamHandle = PamHandle (Ptr Void)

{- |

Used to pass prompting text, error messages, or other informatory text to the
user.

This structure is allocated and freed by the PAM library (or loaded module).

-}

data PamMessage = PamMessage
  { msg_style :: CInt
  , msg :: CString
  }
  deriving (Eq, Show)

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

{- |

Used to return the user's response to the PAM library.

This structure is allocated by the application program, and it is free()'d by
the Linux-PAM library (or calling module).

-}

data PamResponse = PamResponse
  { resp :: CString
  , resp_retcode :: CInt -- ^ currently un-used, zero expected
  }
  deriving (Eq, Show)

instance Storable PamResponse where

  sizeOf    _ = #size      struct pam_response
  alignment _ = #alignment struct pam_response

  peek ptr = do
    resp         <- #{peek struct pam_response, resp}         ptr
    resp_retcode <- #{peek struct pam_response, resp_retcode} ptr
    return PamResponse{..}

  poke ptr PamResponse{..} = do
    #{poke struct pam_response, resp}         ptr resp
    #{poke struct pam_response, resp_retcode} ptr resp_retcode

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
