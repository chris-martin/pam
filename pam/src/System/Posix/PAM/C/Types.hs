{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module System.Posix.PAM.C.Types
  ( CPamHandle
  , CPamMessage (..)
  , CPamResponse (..)
  , ConvFunc
  , CPamConv (..)
  ) where

import Data.Eq (Eq)
import Foreign.C (CInt, CString)
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.CStorable (CStorable(..))
import Foreign.Storable (Storable (..))
import GHC.Generics (Generic)
import Text.Show (Show)
import System.IO (IO)

{- | An opaque handle to a PAM session, obtained using 'c_pam_start' and freed
using 'c_pam_end'.

/You must use a different 'CPamHandle' for each transaction./ -}
type CPamHandle = Ptr ()

{- |

Used to pass prompting text, error messages, or other informatory text to the
user.

/This structure is allocated and freed by the PAM library (or loaded module)./

-}
data CPamMessage = CPamMessage
  { msg_style :: CInt
  , msg :: CString
  }
  deriving (CStorable, Eq, Generic, Show)

instance Storable CPamMessage
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf

{- | Used to return the user's response to the PAM library.

/This structure is allocated by the application program, and it is free()'d by/
/the Linux-PAM library (or calling module)./ -}
data CPamResponse = CPamResponse
  { resp :: CString
  , resp_retcode :: CInt -- ^ currently un-used, zero expected
  }
  deriving (CStorable, Eq, Generic, Show)

instance Storable CPamResponse
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt

{- | The actual conversation structure itself. -}
data CPamConv = CPamConv
  { conv :: FunPtr ConvFunc
  , appdata_ptr :: Ptr ()
  }
  deriving (CStorable, Eq, Generic, Show)

instance Storable CPamConv
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf
