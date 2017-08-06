{-# LANGUAGE DeriveGeneric, DeriveAnyClass, ForeignFunctionInterface #-}

module System.Posix.PAM.Internals
  (
  -- * PAM session management
    CPamHandle
  , c_pam_start
  , c_pam_end

  -- * Conversation protocol
  , CPamMessage (..)
  , CPamResponse (..)
  , CPamConv (..)
  , ConvFunc
  , mkconvFunc

  -- * Authenticating a user
  , c_pam_authenticate
  , PamAuthenticateFlags

  -- * Checking if the authenticated user is valid
  , c_pam_acct_mgmt
  , PamAcctMgmtFlags

  ) where

import Data.Eq (Eq)
import Foreign.C
import Foreign.CStorable (CStorable(..))
import Foreign.Ptr
import Foreign.Storable
import GHC.Generics (Generic)
import Text.Show (Show)
import System.IO (IO)

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

{- |

Used to return the user's response to the PAM library.

/This structure is allocated by the application program, and it is free()'d by/
/the Linux-PAM library (or calling module)./

-}
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

{- |

The actual conversation structure itself.

-}
data CPamConv = CPamConv
  { conv :: FunPtr ConvFunc
  , appdata_ptr :: Ptr ()
  }
  deriving (CStorable, Eq, Generic, Show)

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt
foreign import ccall "wrapper" mkconvFunc :: ConvFunc -> IO (FunPtr ConvFunc)

instance Storable CPamConv
  where
   peek = cPeek
   poke = cPoke
   alignment = cAlignment
   sizeOf = cSizeOf

{- |

An opaque handle to a PAM session, obtained using 'c_pam_start' and freed using
'c_pam_end'.

/You must use a different 'CPamHandle' for each transaction./

-}
type CPamHandle = Ptr ()

{- |

Creates a 'CPamHandle' and initiates a PAM transaction. This is always the first
thing you need to do to use PAM.

/Make sure you call 'pam_end' once the transaction is over./

-}
foreign import ccall "security/pam_appl.h pam_start" c_pam_start
  :: CString -> CString -> Ptr CPamConv -> Ptr CPamHandle -> IO CInt

{- |

Terminates a PAM transaction.

/The 'CPamHandle' will become invalid, so this is the last thing you should do/
/with it./

-}
foreign import ccall "security/pam_appl.h pam_end" c_pam_end
  :: CPamHandle -> CInt -> IO CInt

{- |

This is used to authenticate the user. The user is required to provide an
authentication token depending upon the authentication service. Usually this is
a password, but could also be a fingerprint. The PAM service module may request
that the user enter their username via the conversation mechanism (see
'CPamConv').

-}
foreign import ccall "security/pam_appl.h pam_authenticate" c_pam_authenticate
  :: CPamHandle -- ^ A PAM handle obtained by a prior call to 'c_pam_start'.
  -> PamAuthenticateFlags
  -> IO CInt

{- |

The binary /or/ of zero or more of the following values:

- @PAM_SILENT@ - Do not emit any messages.

- @PAM_DISALLOW_NULL_AUTHTOK@ - The PAM module service should return
  @PAM_AUTH_ERR@ if the user does not have a registered authentication token.

-}
type PamAuthenticateFlags = CInt

{- |

Used to determine if the user's account is valid. It checks for authentication
token and account expiration and verifies access restrictions. This is typically
called after the user has been authenticated.

-}
foreign import ccall "security/pam_appl.h pam_acct_mgmt" c_pam_acct_mgmt
  :: CPamHandle -- ^ A PAM handle obtained by a prior call to 'c_pam_start'.
  -> PamAcctMgmtFlags
  -> IO CInt

{- |

The binary /or/ of zero or more of the following values:

- @PAM_SILENT@ - Do not emit any messages.

- @PAM_DISALLOW_NULL_AUTHTOK@ - The PAM module service should return
  @PAM_AUTH_ERR@ if the user does not have a registered authentication token.

-}
type PamAcctMgmtFlags = CInt
