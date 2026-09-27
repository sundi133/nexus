# Remote Assist

See and control a Mac's screen from the Nexus console to help the person using it. **They're asked first**, can end it at any time, and every step is audited.

## Using it

1. Open the device and choose **Actions → Remote Assist**.
2. Say why, and for how long (15 minutes to 2 hours). This needs `devices:actions` (scoped roles work) and a recent MFA.
3. The person at the Mac sees a prompt with your name and reason: **Allow** or **Don't Allow** (the default). They have a minute to answer. The request reaches the Mac with its next check-in, usually within a minute.
4. Once they allow it, the screen opens in your browser. macOS asks for an account on the Mac, such as an IT admin account. The account and password go to the Mac encrypted for it; Nexus only relays them.
5. Use **View only** to watch without controlling, and **Full screen** for more room.
6. **End session** when you're done. The person at the Mac can also click **End Session** on their screen at any time. Either way, the session ends on its own at the time limit.

Only the person who asked can view. The person at the Mac allowed *them*, not everyone with the same role. Another admin can still end the session.

## What happens on the Mac

- The agent shows the prompt in the signed-in person's session. If nobody is signed in, the request fails: there's nobody to ask.
- If they allow it, the agent turns on macOS **Screen Sharing** for the session, and turns it back off afterwards if it was off before.
- While the session runs, macOS shows its own screen-sharing indicator in the menu bar. The agent keeps an **End Session** prompt on screen.
- The agent opens outbound connections to Nexus only. Nothing listens on the network: Screen Sharing is reached on `127.0.0.1:5900`, and the agent connects nowhere else.

## Audit

| Event | When |
|---|---|
| `remote_assist.requested` | You asked, with your reason |
| `remote_assist.accepted` / `.declined` | The person at the Mac answered (the detail names who) |
| `remote_assist.viewed` | Your browser connected (each connection) |
| `remote_assist.ended` / `.failed` | It ended: by you, by them, at the time limit, or because something went wrong |

The device's **Actions** tab also shows the request as a command.

## How it works

```
browser ──wss──▶ Nexus API relay ◀──wss── agent ──tcp──▶ 127.0.0.1:5900 (Screen Sharing)
```

- The agent's tunnel is a websocket signed with the device key (like every agent call). It's accepted only while the session is active.
- The browser's websocket carries a one-time ticket that expires in a minute. It's issued only to the requester, and only accepted from the console's origin.
- Each viewer connection gets its own tunnel. When the session ends, the relay closes both sides and refuses new tunnels, and the agent cleans up.
- The screen stream is protected by TLS on each hop but passes through the Nexus server. It is not end-to-end encrypted like the [password manager](PASSWORDS.md).

## Setting it up

- **Console build:** set `NEXUS_API_PUBLIC_URL` when building the web app, so its Content-Security-Policy allows the viewer's websocket to the API.
- **Load balancer:** it must pass websocket upgrades on `/v1/agent/remote-assist/` and `/v1/remote-assist/`. With several API instances, both ends of a session must reach the same one. Route those two paths to one instance, or use sticky sessions.
- **Mac control:** Apple limits what Screen Sharing turned on from the command line may do on some macOS versions. If you can see the screen but not control it, turn on **Screen Sharing** once under **System Settings → General → Sharing** on that Mac. The agent then finds it already on and leaves it that way after each session.

## Limits

- **Macs only.** Windows (Quick Assist-style) and Linux are on the roadmap.
- **No sound, file transfer or chat.** Use your usual call tool alongside.
- **Mac sign-in:** macOS Screen Sharing needs an account on the Mac to sign in with.
- **Relay affinity:** the relay runs inside the API process, so a session lives on one instance (see above).
