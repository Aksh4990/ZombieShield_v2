#!/bin/sh
# Starts nginx and reloads it whenever ZombieShield rewrites its gateway rule files
# (on "apply" or "rollback" in the remediation workflow). A rule set that fails `nginx -t`
# is never loaded: the gateway keeps serving the last good configuration.
set -u
RULES=/etc/nginx/zombieshield
fingerprint() { cat "$RULES"/*.conf "$RULES"/http/*.conf 2>/dev/null | md5sum; }

nginx -g "daemon off;" &
pid=$!
last=$(fingerprint)
while kill -0 "$pid" 2>/dev/null; do
  sleep 5
  current=$(fingerprint)
  if [ "$current" != "$last" ]; then
    if nginx -t 2>/tmp/nginx-test.log; then
      nginx -s reload && echo "zombieshield: gateway rules reloaded"
    else
      echo "zombieshield: new gateway rules rejected by nginx -t; keeping the previous configuration" >&2
      cat /tmp/nginx-test.log >&2
    fi
    last=$current
  fi
done
wait "$pid"
