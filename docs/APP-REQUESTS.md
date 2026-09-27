# Asking for blocked apps and software

When the agent stops an app, the person at the computer finds out why. They can ask for it, and their approver decides from the Nexus app on their phone or in the console. People can also ask for software from the App deployment catalog. Both are **access requests**, so they get the same approval chains, time limits, early give-back, revocation and audit trail as apps, groups and admin roles.

## The flow

1. **Stopped.** A block rule closes an app. On a Mac, a Notification Center banner says *"Chess was closed (Chess). If you need it for work, request access in Nexus."* On Windows, a message appears. It's shown at most once every 10 minutes per app.
2. **Notified.** The device's user also gets a Nexus notification in the console and as a push to Nexus Mobile, at most once a day per app. If the rule is requestable, it links straight to the request.
3. **Requested.** They give a reason and choose how long (for example 8 hours), in the console or on the phone.
4. **Approved.** Approvers are notified, and on the phone the push opens **To approve**. They approve (with Face ID or Touch ID on the phone) or deny, stage by stage. Their decisions are audited.
5. **Applied.**
   - **Blocked app:** the rule stops applying to the requester's devices. Their next signed policy, within about a minute, leaves it out. Everyone else stays blocked.
   - **Software:** the app is installed on the requester's devices at their next check-in.
6. **Ended.**
   - **Blocked app:** when the time is up, or someone revokes it, or they give it back, the rule applies again.
   - **Software:** the app stays installed but is no longer kept there. Remove it with a Remove assignment if needed.

## Setting it up

Go to **Access requests → Catalog → Make something requestable**:
- **A blocked app:** pick an app block rule. Domain rules can't have exceptions, because a domain is blocked for the whole device.
- **Software:** pick an app from App deployment.
- **For both:** set the longest duration, whether "permanently" is allowed, the approval stages (the requester's manager, specific people, a group or a role) and, optionally, who is pre-approved.

Rules that aren't in the catalog still notify people. The message then says to ask IT.

## Limits

- **Linux:** no desktop notification yet. People still get the Nexus notification.
- **Admin roles:** requests for admin roles still need a fresh MFA, so they're approved in the console, not on the phone.
- **"The device's user":** means the device's primary user in Nexus. A device without one gets the banner, but no Nexus notification or request link.
