module System.Posix.PAM.Bindings
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

  -- * Return value
  , ReturnValue (..)
  -- $success
  , success

  -- * Error strings
  , pam_strerror

  ) where

import System.Posix.PAM.Bindings.Functions
import System.Posix.PAM.Bindings.Types
import System.Posix.PAM.Bindings.ReturnValue (ReturnValue (..), success)

-- $success
-- 'success' is the only 'ReturnValue' exported from this module; for the rest,
-- see "System.Posix.PAM.Bindings.ReturnValue".
