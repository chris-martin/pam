{-# LANGUAGE CPP #-}

module System.Posix.PAM.Bindings.ReturnValue where

import Foreign.C.Types

#include <security/pam_appl.h>

newtype ReturnValue = ReturnValue CInt
    deriving Eq

-- | Successful function return
success :: ReturnValue
success = ReturnValue #const PAM_SUCCESS

-- | @dlopen()@ failure when dynamically loading a service module
openErr :: ReturnValue
openErr = ReturnValue #const PAM_OPEN_ERR

-- | Symbol not found
symbolErr :: ReturnValue
symbolErr = ReturnValue #const PAM_SYMBOL_ERR

-- | Error in service module
serviceErr :: ReturnValue
serviceErr = ReturnValue #const PAM_SERVICE_ERR

-- | System error
systemErr :: ReturnValue
systemErr = ReturnValue #const PAM_SYSTEM_ERR

-- | Memory buffer error
bufErr :: ReturnValue
bufErr = ReturnValue #const PAM_BUF_ERR

-- | Permission denied */
permDenied :: ReturnValue
permDenied = ReturnValue #const PAM_PERM_DENIED

-- | Authentication failure
authErr :: ReturnValue
authErr = ReturnValue #const PAM_AUTH_ERR

-- | Can not access authentication data due to insufficient credentials
credInsufficient :: ReturnValue
credInsufficient = ReturnValue #const PAM_CRED_INSUFFICIENT

-- | Underlying authentication service can not retrieve authentication
-- information
authinfoUnavail :: ReturnValue
authinfoUnavail = ReturnValue #const PAM_AUTHINFO_UNAVAIL

-- | User not known to the underlying authentication module */
userUnknown :: ReturnValue
userUnknown = ReturnValue #const PAM_USER_UNKNOWN

-- | An authentication service has maintained a retry count which has been
-- reached.  No further retries should be attempted
maxtries :: ReturnValue
maxtries = ReturnValue #const PAM_MAXTRIES

-- | New authentication token required. This is normally returned if the
-- machine security policies require that the password should be changed
-- because the password is NULL or it has aged
newAuthtokReqd :: ReturnValue
newAuthtokReqd = ReturnValue #const PAM_NEW_AUTHTOK_REQD

-- | User account has expired
acctExpired :: ReturnValue
acctExpired = ReturnValue #const PAM_ACCT_EXPIRED

-- | Can not make/remove an entry for the specified session
sessionErr :: ReturnValue
sessionErr = ReturnValue #const PAM_SESSION_ERR

-- | Underlying authentication service can not retrieve user credentials
-- unavailable
credUnavail :: ReturnValue
credUnavail = ReturnValue #const PAM_CRED_UNAVAIL

-- | User credentials expired
credExpired :: ReturnValue
credExpired = ReturnValue #const PAM_CRED_EXPIRED

-- | Failure setting user credentials
credErr :: ReturnValue
credErr = ReturnValue #const PAM_CRED_ERR

-- | No module specific data is present
noModuleData :: ReturnValue
noModuleData = ReturnValue #const PAM_NO_MODULE_DATA

-- | Conversation error
convErr :: ReturnValue
convErr = ReturnValue #const PAM_CONV_ERR

-- | Authentication token manipulation error
authtokErr :: ReturnValue
authtokErr = ReturnValue #const PAM_AUTHTOK_ERR

-- | Authentication information cannot be recovered
authtokRecoveryErr :: ReturnValue
authtokRecoveryErr = ReturnValue #const PAM_AUTHTOK_RECOVERY_ERR

-- | Authentication token lock busy
authtokLockBusy :: ReturnValue
authtokLockBusy = ReturnValue #const PAM_AUTHTOK_LOCK_BUSY

-- | Authentication token aging disabled
authtokDisableAging :: ReturnValue
authtokDisableAging = ReturnValue #const PAM_AUTHTOK_DISABLE_AGING

-- | Preliminary check by password service
tryAgain :: ReturnValue
tryAgain = ReturnValue #const PAM_TRY_AGAIN

-- | Ignore underlying account module regardless of whether the control flag
-- is required, optional, or sufficient
ignore :: ReturnValue
ignore = ReturnValue #const PAM_IGNORE

-- | Critical error (?module fail now request)
abort :: ReturnValue
abort = ReturnValue #const PAM_ABORT

-- | User's authentication token has expired
authtokExpired :: ReturnValue
authtokExpired = ReturnValue #const PAM_AUTHTOK_EXPIRED

-- | Module is not known
moduleUnknown :: ReturnValue
moduleUnknown = ReturnValue #const PAM_MODULE_UNKNOWN

-- | Bad item passed to @pam_*_item()@
badItem :: ReturnValue
badItem = ReturnValue #const PAM_BAD_ITEM

-- | Conversation function is event driven and data is not available yet
convAgain :: ReturnValue
convAgain = ReturnValue #const PAM_CONV_AGAIN
