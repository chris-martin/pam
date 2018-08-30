module System.Posix.PAM.Bindings
  (
  -- * PAM session management
    Handle
  , pam_start
  , pam_end

  -- * Conversation protocol
  , PamMessage (..)
  , Response (..)
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
import System.Posix.PAM.Bindings.Handle
import System.Posix.PAM.Bindings.Response (Response (..))
import System.Posix.PAM.Bindings.ReturnValue (ReturnValue (..), success)
import System.Posix.PAM.Bindings.Types

-- $success
-- 'success' is the only 'ReturnValue' exported from this module; for the rest,
-- see "System.Posix.PAM.Bindings.ReturnValue".
