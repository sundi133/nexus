#!/bin/sh
# Stops the agent when the package is removed, not when it's upgraded
# (dpkg passes "remove"; rpm passes 0 on erase and 1 on upgrade).
case "$1" in
  remove|purge|0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now nexus-agent.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
