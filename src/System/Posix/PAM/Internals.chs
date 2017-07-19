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

An opaque handle to PAM, obtained using 'c_pam_start'.

-}
type CPamHandle = Ptr ()

foreign import ccall "security/pam_appl.h pam_start" c_pam_start :: CString -> CString -> Ptr CPamConv -> Ptr CPamHandle -> IO CInt
foreign import ccall "security/pam_appl.h pam_end" c_pam_end :: CPamHandle -> CInt -> IO CInt
foreign import ccall "security/pam_appl.h pam_authenticate" c_pam_authenticate :: CPamHandle -> CInt -> IO CInt
foreign import ccall "security/pam_appl.h pam_acct_mgmt" c_pam_acct_mgmt :: CPamHandle -> CInt -> IO CInt
foreign import ccall "security/pam_misc.h misc_conv" c_misc_conv :: CInt -> Ptr (Ptr ()) -> Ptr (Ptr ()) -> Ptr () -> IO CInt
