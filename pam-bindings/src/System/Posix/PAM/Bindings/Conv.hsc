{-# LANGUAGE CPP, GeneralizedNewtypeDeriving, RecordWildCards #-}

module System.Posix.PAM.Bindings.Conv
  ( ConvFunc
  , Conv (..)
  ) where

import Foreign.C (CInt)
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.Storable (Storable (..))

#include <security/pam_appl.h>

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt

{- |

The actual conversation structure itself.

-}

data Conv = Conv
  { conv :: FunPtr ConvFunc
  , appdata_ptr :: Ptr ()
  }
  deriving (Eq, Show)

instance Storable Conv where

  sizeOf    _ = #size      struct pam_conv
  alignment _ = #alignment struct pam_conv

  peek ptr = do
    conv        <- #{peek struct pam_conv, conv}        ptr
    appdata_ptr <- #{peek struct pam_conv, appdata_ptr} ptr
    return Conv{..}

  poke ptr Conv{..} = do
    #{poke struct pam_conv, conv}        ptr conv
    #{poke struct pam_conv, appdata_ptr} ptr appdata_ptr
