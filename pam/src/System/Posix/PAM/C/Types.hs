{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module System.Posix.PAM.C.Types
  ( PamHandle
  , PamMessage (..)
  , PamResponse (..)
  , ConvFunc
  , PamConv (..)
  ) where

import Data.Eq (Eq)
import Foreign.C (CInt, CString)
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.CStorable (CStorable(..))
import Foreign.Storable (Storable (..))
import GHC.Generics (Generic)
import Text.Show (Show)
import System.IO (IO)

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
  deriving (CStorable, Eq, Generic, Show)

instance Storable PamMessage
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf

{- | Used to return the user's response to the PAM library.

/This structure is allocated by the application program, and it is free()'d by/
/the Linux-PAM library (or calling module)./ -}
data PamResponse = PamResponse
  { resp :: CString
  , resp_retcode :: CInt -- ^ currently un-used, zero expected
  }
  deriving (CStorable, Eq, Generic, Show)

instance Storable PamResponse
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt

{- | The actual conversation structure itself. -}
data PamConv = PamConv
  { conv :: FunPtr ConvFunc
  , appdata_ptr :: Ptr ()
  }
  deriving (CStorable, Eq, Generic, Show)

instance Storable PamConv
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf
