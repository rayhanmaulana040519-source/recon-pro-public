#!/system/bin/sh
# phone.sh - one network round trip instead of many.
#
# Deploy: adb push phone.sh /sdcard/phone/phone.sh
# Use:    adb shell sh /sdcard/phone/phone.sh <command> [args]
#
# Every separate adb call costs a full round trip, and a UI step usually needs
# dump + search + tap + dump again. These commands do all of that on the device
# and return one short answer: "text<TAB>x,y<TAB>clickable", one line per node.
#
#   dump [limit]              compact screen dump (default 80 lines)
#   tap <text> [limit]        find text, tap it, return the new screen
#   tapxy <x> <y>             tap exact coordinates
#   swipe <x1> <y1> <x2> <y2> [ms]
#   type <text>               type into the focused field
#   key back|home|recents|enter
#   open <package>            launch an app
#   wait <ms>
#   shot [path]               full screenshot (default /sdcard/phone/shot.png)
#   win                       current focused window
set -u

DUMP_DIR=/sdcard/phone
DUMP=$DUMP_DIR/window.xml
mkdir -p "$DUMP_DIR" 2>/dev/null

dump_xml() {
    uiautomator dump "$DUMP" >/dev/null 2>&1 || return 1
    [ -s "$DUMP" ] || return 1
    return 0
}

compact() {
    tr '\n' ' ' < "$DUMP" | sed 's/<node /\n<node /g' | awk '
    {
        line = $0
        text = ""
        desc = ""
        if (match(line, /text="[^"]*"/)) text = substr(line, RSTART + 6, RLENGTH - 7)
        if (text == "" && match(line, /content-desc="[^"]*"/)) desc = substr(line, RSTART + 14, RLENGTH - 15)
        label = (text != "" ? text : desc)
        if (label == "") next
        if (!match(line, /bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"/)) next
        box = substr(line, RSTART + 8, RLENGTH - 9)
        gsub(/[^0-9]+/, " ", box)
        split(box, p, " ")
        cx = int((p[1] + p[3]) / 2)
        cy = int((p[2] + p[4]) / 2)
        click = (line ~ /clickable="true"/) ? "1" : "0"
        printf "%s\t%d,%d\t%s\n", label, cx, cy, click
    }'
}

find_xy() {
    compact | awk -v want="$1" '
    BEGIN { want = tolower(want) }
    {
        key = tolower($1)
        if (key == want && !found) { print $2; found = 1; exit }
        if (best == "" && index(key, want) > 0) best = $2
    }
    END { if (!found && best != "") print best }'
}

cmd="${1:-}"
[ $# -gt 0 ] && shift

case "$cmd" in
    dump)
        limit="${1:-80}"
        dump_xml || { echo "dump gagal"; exit 1; }
        compact | head -n "$limit"
        ;;
    tap)
        want="${1:-}"
        limit="${2:-40}"
        [ -n "$want" ] || { echo "pemakaian: tap <text> [limit]"; exit 2; }
        dump_xml || { echo "dump gagal"; exit 1; }
        xy=$(find_xy "$want")
        if [ -z "$xy" ]; then
            echo "tidak ketemu: $want"
            compact | head -n 30
            exit 1
        fi
        x=${xy%,*}
        y=${xy#*,}
        input tap "$x" "$y"
        sleep 0.4
        if dump_xml; then
            compact | head -n "$limit"
        fi
        ;;
    tapxy)
        input tap "${1:?x}" "${2:?y}"
        ;;
    swipe)
        input swipe "${1:?x1}" "${2:?y1}" "${3:?x2}" "${4:?y2}" "${5:-300}"
        ;;
    type)
        input text "$(printf '%s' "${1:-}" | sed 's/ /%s/g')"
        ;;
    key)
        case "${1:-}" in
            back) input keyevent 4 ;;
            home) input keyevent 3 ;;
            recents) input keyevent 187 ;;
            enter) input keyevent 66 ;;
            *) echo "pemakaian: key back|home|recents|enter"; exit 2 ;;
        esac
        ;;
    open)
        monkey -p "${1:?package}" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
        ;;
    wait)
        sleep "$(awk -v ms="${1:-500}" 'BEGIN { printf "%.3f", ms / 1000 }')"
        ;;
    shot)
        out="${1:-$DUMP_DIR/shot.png}"
        screencap -p "$out" && echo "$out"
        ;;
    win)
        dumpsys window 2>/dev/null | grep -E 'mCurrentFocus|mFocusedApp' | head -n 2
        ;;
    *)
        echo "phone.sh: dump|tap|tapxy|swipe|type|key|open|wait|shot|win"
        exit 2
        ;;
esac
