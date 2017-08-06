module System.Posix.PAM.C
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

  -- * Error strings
  , c_pam_strerror

  ) where

import System.Posix.PAM.C.Functions
import System.Posix.PAM.C.Types
