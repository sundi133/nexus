# Sign in with this computer

On a work computer running the Nexus agent, people sign in to the console without typing an email or a password. The agent vouches for the computer, and Touch ID or Windows Hello for the person. It's the same idea as JumpCloud Go.

## Setting it up (once per computer)

On the computer, sign in as usual, then go to **My security → Sign in with this computer → Set up on this computer**:

1. The console asks the local Nexus agent to confirm which enrolled computer this is.
2. The browser makes a passkey on the computer (Touch ID or Windows Hello).
3. Nexus binds that passkey to the computer.

It works only on a computer that's **assigned to you**.

## Signing in

On the sign-in page, choose **Sign in with this computer**:

1. The page asks the local agent to sign a one-time nonce. The agent answers only the Nexus console's origin, and names that origin in what it signs.
2. Nexus checks the signature against the enrolled device's key, then finds the person it's assigned to. The computer must be enrolled and active, assigned to someone, and not failing your device policies.
3. The browser asks for Touch ID or Windows Hello, using only the passkey bound to this computer.
4. Nexus checks the passkey, and that the computer is still assigned to the same person, then starts the session.

The session starts **device-verified**, so conditional access rules that require a managed or compliant device are already satisfied.

It's phishing-resistant: the passkey is bound to the Nexus origin, and the agent won't vouch for another site. Every sign-in is in the audit log as `auth.login` with `method: device`, naming the computer.

## When it isn't offered

| Message | Why |
|---|---|
| The Nexus agent isn't answering | The agent isn't installed or running, or it's enrolled to a different console |
| Isn't assigned to anyone | Shared computers can't sign a specific person in: use your email |
| Doesn't meet your device policies | Fix what **My devices** shows, or sign in with your email |
| Isn't set up yet | Set it up once from **My security** |
| Sign in with your IdP | Your organization requires its identity provider for your email |

**Reassigning** a computer to someone else stops its bound passkeys from working, straight away. **Removing** it from My security leaves the passkey as an ordinary passkey.

## Limits

- **Console only, in a browser:** not the mobile app or the CLI, and not SSO into other apps yet (they sign in through the console, so a signed-in console session covers them).
- **Nexus's own sign-in page only:** not the macOS or Windows login window.
