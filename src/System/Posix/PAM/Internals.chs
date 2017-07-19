{-# LANGUAGE CPP, ForeignFunctionInterface #-}
module System.Posix.PAM.Internals where

import Control.Applicative
import Foreign.C
import Foreign.Ptr
import Foreign.Storable

#include <security/pam_appl.h>
#include <security/pam_misc.h>

{- |

Used to pass prompting text, error messages, or other informatory text to the
user.

/This structure is allocated and freed by the PAM library (or loaded module)./

-}
data CPamMessage = CPamMessage { msg_style :: CInt
                               , msg :: CString
                               }
                               deriving (Show,Eq)

instance Storable CPamMessage where
    alignment _ = alignment (undefined :: CDouble)
    sizeOf _ = sizeOf (undefined :: CInt) + sizeOf (undefined :: CString)
    peek p = CPamMessage <$> ({#get pam_message.msg_style #} p)
                         <*> ({#get pam_message.msg #} p)
    poke p (CPamMessage ms m) = do
        {#set pam_message.msg_style #} p ms
        {#set pam_message.msg #} p m

{- |

Used to return the user's response to the PAM library.

/This structure is allocated by the application program, and it is free()'d by/
/the Linux-PAM library (or calling module)./

-}
data CPamResponse = CPamResponse
    { resp :: CString
    , resp_retcode :: CInt -- ^ currently un-used, zero expected
    }
    deriving (Show,Eq)

instance Storable CPamResponse where
    alignment _ = alignment (undefined :: CDouble)
    sizeOf _ = sizeOf (undefined :: CString) + sizeOf (undefined :: CInt)
    peek p = CPamResponse <$> ({#get pam_response.resp #} p)
                          <*> ({#get pam_response.resp_retcode #} p)
    poke p (CPamResponse r rc) = do
        {#set pam_response.resp #} p r
        {#set pam_response.resp_retcode #} p rc

{- |

The actual conversation structure itself.

-}
data CPamConv = CPamConv { conv :: FunPtr (CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt)
                         , appdata_ptr :: Ptr ()
                         }
                         deriving (Show, Eq)

type ConvFunc = CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt
foreign import ccall "wrapper" mkconvFunc :: ConvFunc -> IO (FunPtr ConvFunc)

instance Storable CPamConv where
    alignment _ = alignment (undefined :: CDouble)
    sizeOf _ = sizeOf (undefined :: FunPtr ()) + sizeOf (undefined :: Ptr ())
    peek p = CPamConv <$> ({#get pam_conv.conv #} p)
                      <*> ({#get pam_conv.appdata_ptr #} p)
    poke p (CPamConv c ap) = do
        {#set pam_conv.conv #} p c
        {#set pam_conv.appdata_ptr #} p ap

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
foreign import ccall "security/pam_appl.h pam_start" c_pam_start :: CString -> CString -> Ptr CPamConv -> Ptr CPamHandle -> IO CInt

{- |

Terminates a PAM transaction.

/The 'CPamHandle' will become invalid, so this is the last thing you should do/
/with it./

-}
foreign import ccall "security/pam_appl.h pam_end" c_pam_end :: CPamHandle -> CInt -> IO CInt

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

foreign import ccall "security/pam_appl.h pam_acct_mgmt" c_pam_acct_mgmt :: CPamHandle -> CInt -> IO CInt

foreign import ccall "security/pam_misc.h misc_conv" c_misc_conv :: CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt
