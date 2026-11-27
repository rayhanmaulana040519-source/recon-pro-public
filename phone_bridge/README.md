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

## Limits

- The device must be **unlocked**. A locked screen (keyguard) dumps an empty
  hierarchy, so `dump` and `tap` return nothing until `deviceLocked=0`.
- Runs as the `shell` user (`adb shell`), so it needs no root and no extra app.
- Text matching is exact first, then case-insensitive contains; the first match
  is used, so pass distinctive text.
- `type` sends `%s` for spaces; `input text` cannot do newlines.
