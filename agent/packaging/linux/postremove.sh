#!/bin/sh
# The device key and enrollment in /var/lib/nexus-agent are kept, so reinstalling resumes the same
# device. `apt purge` removes them too (then remove the device in the Nexus console).
if [ "$1" = "purge" ]; then
  rm -rf /var/lib/nexus-agent
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
