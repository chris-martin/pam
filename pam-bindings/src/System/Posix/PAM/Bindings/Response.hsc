{-# LANGUAGE CPP, GeneralizedNewtypeDeriving, RecordWildCards #-}

module System.Posix.PAM.Bindings.Response
  ( Response (..)
  ) where

import Foreign.C (CInt, CString)
import Foreign.Storable (Storable (..))

#include <security/pam_appl.h>

{- |

Used to return the user's response to the PAM library.

This structure is allocated by the application program, and it is @free()@'d
by the Linux-PAM library (or calling module).

-}

data Response = Response
  { resp :: CString
  , resp_retcode :: CInt -- ^ currently un-used, zero expected
  }
  deriving (Eq, Show)

instance Storable Response where

  sizeOf    _ = #size      struct pam_response
  alignment _ = #alignment struct pam_response

  peek ptr = do
    resp         <- #{peek struct pam_response, resp}         ptr
    resp_retcode <- #{peek struct pam_response, resp_retcode} ptr
    return Response{..}

  poke ptr Response{..} = do
    #{poke struct pam_response, resp}         ptr resp
    #{poke struct pam_response, resp_retcode} ptr resp_retcode
