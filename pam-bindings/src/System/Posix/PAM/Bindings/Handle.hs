{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module System.Posix.PAM.Bindings.Handle where

import Data.Void (Void)
import Foreign.Ptr (Ptr)
import Foreign.Storable (Storable)

{- |

An opaque handle to a PAM session, obtained using 'pam_start' and freed using
'pam_end'.

You must use a different 'Handle' for each transaction.

-}

newtype Handle = Handle (Ptr Void) deriving Storable
