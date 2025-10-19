This boilerplate project is designed to be a comprehensive Rio app starter that has all the basic functionality needed to build a production ready webapp.


It is built upon on the rio-auth template from the core library.

## Two-Factor Recovery Codes

- Enabling MFA now generates a one-time list of backup recovery codes so accounts remain accessible if an authenticator device is lost.
- Visit `Settings → Manage Recovery Codes` (`/app/recovery-codes`) to regenerate a fresh set. Regeneration immediately invalidates older codes, so remind users to store the new list securely.
