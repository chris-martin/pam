{-# LANGUAGE ForeignFunctionInterface #-}

module System.Posix.PAM.Bindings.Functions
  ( pam_start, pam_end
  , mkconvFunc
  , pam_authenticate, PamAuthenticateFlags
  , pam_acct_mgmt, PamAcctMgmtFlags
  , pam_strerror
  ) where

import System.Posix.PAM.Bindings.Conv (Conv (..), ConvFunc)
import System.Posix.PAM.Bindings.Handle (Handle (..))
import System.Posix.PAM.Bindings.ReturnValue (ReturnValue (..))

import Foreign.C (CInt (..), CString)
import Foreign.Ptr (FunPtr, Ptr)

foreign import ccall "wrapper" mkconvFunc
  :: ConvFunc -> IO (FunPtr ConvFunc)

{- |

Creates a 'PamHandle' and initiates a PAM transaction. This is always the first
thing you need to do to use PAM.

Make sure you call 'pam_end' once the transaction is over.

-}

foreign import ccall "security/pam_appl.h pam_start" pam_start
  :: CString -> CString -> Ptr Conv -> Ptr Handle -> IO ReturnValue

{- |

Terminates a PAM transaction.

The 'PamHandle' will become invalid, so this is the last thing you should do
with it.

-}

foreign import ccall "security/pam_appl.h pam_end" pam_end
  :: Handle -> CInt -> IO ReturnValue

{- |

This is used to authenticate the user. The user is required to provide an
authentication token depending upon the authentication service. Usually this is
a password, but could also be a fingerprint. The PAM service module may request
that the user enter their username via the conversation mechanism (see
'CPamConv').


-}
foreign import ccall "security/pam_appl.h pam_authenticate" pam_authenticate
  :: Handle -- ^ A PAM handle obtained by a prior call to 'pam_start'.
  -> PamAuthenticateFlags
  -> IO ReturnValue

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

foreign import ccall "security/pam_appl.h pam_acct_mgmt" pam_acct_mgmt
  :: Handle -- ^ A PAM handle obtained by a prior call to 'pam_start'.
  -> PamAcctMgmtFlags
  -> IO ReturnValue

{- |

The binary /or/ of zero or more of the following values:

- @PAM_SILENT@ - Do not emit any messages.

- @PAM_DISALLOW_NULL_AUTHTOK@ - The PAM module service should return
  @PAM_AUTH_ERR@ if the user does not have a registered authentication token.

-}

type PamAcctMgmtFlags = CInt

{- |

Returns a pointer to a string describing the error code passed in the argument
errnum, possibly using the @LC_MESSAGES@ part of the current locale to select
the appropriate language.

-}

foreign import ccall "security/pam_appl.h pam_strerror" pam_strerror
  :: Handle   -- ^ A PAM handle obtained by a prior call to 'pam_start'.
  -> ReturnValue -- ^ A PAM error code.
  -> IO CString
