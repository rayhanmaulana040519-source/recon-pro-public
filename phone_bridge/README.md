# phone.sh — one round trip instead of many

`adb shell` costs one network round trip per call, and a UI step normally needs
dump + search + tap + dump. This script does the whole step on the phone and
returns a short answer, so the VPS (or an agent) pays one round trip.

## Deploy

```bash
adb shell 'mkdir -p /sdcard/phone'
adb push phone.sh /sdcard/phone/phone.sh
```

## Use

```bash
adb shell sh /sdcard/phone/phone.sh win
adb shell sh /sdcard/phone/phone.sh dump 20
adb shell sh /sdcard/phone/phone.sh tap "Login"
adb shell sh /sdcard/phone/phone.sh tapxy 540 1900
adb shell sh /sdcard/phone/phone.sh key back
adb shell sh /sdcard/phone/phone.sh shot /sdcard/phone/a.png
```

`dump` prints one line per labelled node: `text<TAB>x,y<TAB>clickable`, which is
far smaller than `uiautomator`'s XML and already carries tap coordinates.

## Why it is faster

| Step | Separate calls | With phone.sh |
|---|---|---|
| tap a button by text | dump, search, tap, dump = 3–4 round trips | 1 round trip |
| read screen | 1 round trip + full XML | 1 round trip + short list |

The device still needs ~0.3–0.8s for `uiautomator dump`; this script only removes
the network cost, which is the part the VPS cannot avoid.

## Setup (ATX app + supervisor)

`phone.sh` talks to the ATX app's JSON-RPC server on `127.0.0.1:9008`, which is
what makes it fast. Install once (MIUI needs *Developer options → Install via
USB* enabled, otherwise `pm install` fails with `INSTALL_FAILED_USER_RESTRICTED`):

```bash
adb shell 'cd /sdcard && curl -sL -O https://github.com/openatx/android-uiautomator-server/releases/download/2.4.0/app-uiautomator.apk && curl -sL -O https://github.com/openatx/android-uiautomator-server/releases/download/2.4.0/app-uiautomator-test.apk'
adb shell 'cp /sdcard/app-uiautomator*.apk /data/local/tmp/ && pm install -r -t /data/local/tmp/app-uiautomator.apk && pm install -r -t /data/local/tmp/app-uiautomator-test.apk'
```

Then copy `phone.sh` and `supervise.sh` to `/sdcard/phone/`, start the server and
the supervisor:

```bash
adb shell 'nohup setsid sh /sdcard/phone/supervise.sh >/dev/null 2>&1 &'
adb shell sh /sdcard/phone/phone.sh ping   # pong
```

`supervise.sh` re-starts the instrumentation whenever `/ping` stops answering, so
the server survives crashes. After a phone reboot, start `supervise.sh` once.

## Reading the screen without pixels

`describe` reads the accessibility tree — the same source TalkBack uses — and
prints the screen as text: role, label, centre coordinates and state
(`klik`, `mati`, `fokus`, `terpilih`, `bisa-scroll`, `sandi`).

```
app     : com.mi.android.globallauncher
layar   : 1080x2400
keyboard: mInputShown=false
TextView   Komunikasi   385,191   klik
ImageView  Buka setelan Laci aplikasi   992,191   klik
```

That is enough to understand and drive most screens at ~450ms, no image
involved. Screenshots (`shot`) are only needed for colours, images, games and
custom-canvas views that expose no usable node.

## Measured on the POCO X5 Pro

| Step | Cost |
|---|---|
| Network round trip (VPS ↔ phone over Tailscale/hotspot) | ~93 ms average |
| `uiautomator dump` (old path) | **~2.1 s** — a fresh JVM every call |
| `dumpWindowHierarchy` RPC + compact | **~215–330 ms** |
| Full `tap "<text>"` (dump + find + click + dump) | **~1.0 s** |
| `tapby "<text>"` (server-side click only) | **~0.7 s** |

## Limits


- The device must be **unlocked**. A locked screen (keyguard) dumps an empty
  hierarchy, so `dump` and `tap` return nothing until `deviceLocked=0`.
- Runs as the `shell` user (`adb shell`), so it needs no root and no extra app.
- Text matching is exact first, then case-insensitive contains; the first match
  is used, so pass distinctive text.
- `type` sends `%s` for spaces; `input text` cannot do newlines.
