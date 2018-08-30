{-# LANGUAGE CPP, GeneralizedNewtypeDeriving #-}

module System.Posix.PAM.Bindings.MessageStyle where

import Foreign.C.Types (CInt)
import Foreign.Storable (Storable)

#include <security/pam_appl.h>

newtype MessageStyle = MessageStyle CInt
    deriving (Eq, Storable)

promptEchoOff :: MessageStyle
promptEchoOff = MessageStyle #const PAM_PROMPT_ECHO_OFF

promptEchoOn :: MessageStyle
promptEchoOn = MessageStyle #const PAM_PROMPT_ECHO_ON

errorMsg :: MessageStyle
errorMsg = MessageStyle #const PAM_ERROR_MSG

textInfo :: MessageStyle
textInfo = MessageStyle #const PAM_TEXT_INFO
