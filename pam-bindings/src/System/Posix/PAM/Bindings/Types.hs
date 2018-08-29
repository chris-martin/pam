{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module System.Posix.PAM.Bindings.Types
  ( PamHandle
  , PamMessage (..)
  , PamResponse (..)
  , ConvFunc
  , PamConv (..)
  ) where

import Foreign.C (CInt, CString)
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.Storable.Generic (GStorable (..))
import GHC.Generics (Generic)

{- | An opaque handle to a PAM session, obtained using 'pam_start' and freed
using 'pam_end'.

/You must use a different 'PamHandle' for each transaction./ -}
type PamHandle = Ptr ()

{- | Used to pass prompting text, error messages, or other informatory text to
the user.

/This structure is allocated and freed by the PAM library (or loaded module)./
-}
data PamMessage = PamMessage
  { msg_style :: CInt
  , msg :: CString
  }
  deriving (GStorable, Eq, Generic, Show)

{- | Used to return the user's response to the PAM library.

/This structure is allocated by the application program, and it is free()'d by/
/the Linux-PAM library (or calling module)./ -}
data PamResponse = PamResponse
  { resp :: CString
  , resp_retcode :: CInt -- ^ currently un-used, zero expected
  }
  deriving (GStorable, Eq, Generic, Show)

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt

{- | The actual conversation structure itself. -}
data PamConv = PamConv
  { conv :: FunPtr ConvFunc
  , appdata_ptr :: Ptr ()
  }
  deriving (GStorable, Eq, Generic, Show)
