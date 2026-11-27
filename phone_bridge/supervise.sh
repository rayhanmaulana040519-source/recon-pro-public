#!/system/bin/sh
# Keep the ATX JSON-RPC server alive: restart the instrumentation when /ping
# stops answering. Deployed to /sdcard/phone/supervise.sh and started detached;
# after a reboot just start it again (it re-arms everything else by itself).
set -u
while :; do
    if ! curl -s -m 3 http://127.0.0.1:9008/ping 2>/dev/null | grep -q pong; then
        am force-stop com.github.uiautomator >/dev/null 2>&1
        am instrument -w -e debug false -e class com.github.uiautomator.stub.Stub \
            com.github.uiautomator.test/androidx.test.runner.AndroidJUnitRunner >/dev/null 2>&1 &
        sleep 6
    fi
    sleep 5
done
