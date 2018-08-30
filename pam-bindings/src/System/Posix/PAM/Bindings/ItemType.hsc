{-# LANGUAGE CPP #-}

module System.Posix.PAM.Bindings.ItemType where

import Foreign.C.Types

#include <security/pam_appl.h>

newtype ItemType = ItemType CInt
    deriving Eq

-- | The service name
service :: ItemType
service = ItemType #const PAM_SERVICE

-- | The user name
user :: ItemType
user = ItemType #const PAM_USER

-- | The tty name
tty :: ItemType
tty = ItemType #const PAM_TTY

-- | The remote host name
rhost :: ItemType
rhost = ItemType #const PAM_RHOST

-- | The @pam_conv@ structure
conv :: ItemType
conv = ItemType #const PAM_CONV

-- | The authentication token (password)
authtok :: ItemType
authtok = ItemType #const PAM_AUTHTOK

-- | The old authentication token
oldauthtok :: ItemType
oldauthtok = ItemType #const PAM_OLDAUTHTOK

-- | The remote user name
ruser :: ItemType
ruser = ItemType #const PAM_RUSER

-- | The prompt for getting a username
userPrompt :: ItemType
userPrompt = ItemType #const PAM_USER_PROMPT

-- | App supplied function to override failure delays
failDelay :: ItemType
failDelay = ItemType #const PAM_FAIL_DELAY

-- | X display name
xdisplay :: ItemType
xdisplay = ItemType #const PAM_XDISPLAY

-- | X server authentication data
xauthdata :: ItemType
xauthdata = ItemType #const PAM_XAUTHDATA

-- | The type for @pam_get_authtok@
authtokType :: ItemType
authtokType = ItemType #const PAM_AUTHTOK_TYPE
