#!/bin/sh
# Starts the agent. To enroll, either drop /var/lib/nexus-agent/enroll.conf (server=… and token=…
# lines, as configuration management would) and the service enrolls itself, or run:
#   sudo nexus-agent install --server <url> --token <token>
set -e
chmod 700 /var/lib/nexus-agent
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable nexus-agent.service >/dev/null 2>&1 || true
  # Upgrade or first install: (re)start on the new binary. Not enrolled yet? It waits for enroll.conf.
  systemctl restart nexus-agent.service || true
fi
if [ ! -f /var/lib/nexus-agent/enrollment.json ] && [ ! -f /var/lib/nexus-agent/enroll.conf ]; then
  echo "Nexus agent installed. Enroll this device with: sudo nexus-agent install --server <url> --token <token>"
fi
exit 0
