{- |

This module contains foreign bindings for @security/pam_appl.h@, which defines
the PAM API.

-}

module System.Posix.PAM.C
  (
  -- * PAM session management
    PamHandle
  , pam_start
  , pam_end

  -- * Conversation protocol
  , PamMessage (..)
  , PamResponse (..)
  , PamConv (..)
  , ConvFunc
  , mkconvFunc

  -- * Authenticating a user
  , pam_authenticate
  , PamAuthenticateFlags

  -- * Checking if the authenticated user is valid
  , pam_acct_mgmt
  , PamAcctMgmtFlags

  -- * Error strings
  , pam_strerror

  ) where

import System.Posix.PAM.C.Functions
import System.Posix.PAM.C.Types
