#!/system/bin/sh
# phone.sh - read the phone screen as text (accessibility tree, no screenshots).
#
# Needs the ATX app (com.github.uiautomator) running its JSON-RPC server; see
# README.md for the install and supervise.sh for keeping it alive.
#
# Use: adb shell sh /sdcard/phone/phone.sh <command> [args]
#
#   describe [limit]    app, screen size, keyboard, then every element as
#                       role | label | x,y | flags  (clickable/disabled/focused/...)
#   dump [limit]        the same element list without the header
#   tap <text> [limit]  find text, tap it, return the new screen
#   tapby <text>        server-side click by text (no dump)
#   tapxy <x> <y>
#   swipe <x1> <y1> <x2> <y2> [steps]
#   type <text>         set text of the first EditText
#   key back|home|recent|enter|power
#   open <package>
#   wait <ms>
#   shot [path]         screenshot, only when pixels are actually needed
#   win                 current package
#   ping                is the server alive
set -u

DUMP_DIR=/sdcard/phone
DUMP=$DUMP_DIR/window.xml
RPC=http://127.0.0.1:9008/jsonrpc/0
mkdir -p "$DUMP_DIR" 2>/dev/null

rpc() {
    # $1 = JSON params array, $2 = method
    printf '{"jsonrpc":"2.0","method":"%s","id":1,"params":%s}' "$2" "$1" | \
        curl -s -m 20 -X POST -H 'Content-Type: application/json' -d @- "$RPC"
}

dump_xml() {
    rpc '[true]' dumpWindowHierarchy | \
        sed -n 's/^.*"result":"//; s/"}$//p' | \
        sed 's/\\[rn]/\n/g; s/\\"/"/g' > "$DUMP"
    [ -s "$DUMP" ]
}

# role <TAB> label <TAB> x,y <TAB> flags
compact() {
    tr "\n" " " < "$DUMP" | sed 's/<node /\n<node /g' | awk '
    {
        line = $0
        text = ""; desc = ""; cls = "View"
        if (match(line, /text="[^"]*"/)) text = substr(line, RSTART + 6, RLENGTH - 7)
        if (text == "" && match(line, /content-desc="[^"]*"/)) desc = substr(line, RSTART + 14, RLENGTH - 15)
        if (match(line, /class="[^"]*"/)) { cls = substr(line, RSTART + 7, RLENGTH - 8); sub(/.*\./, "", cls) }
        label = (text != "" ? text : desc)
        if (label == "" && cls ~ /EditText/) label = "(kolom kosong)"
        if (label == "") next
        if (!match(line, /bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"/)) next
        box = substr(line, RSTART + 8, RLENGTH - 9)
        gsub(/[^0-9]+/, " ", box)
        split(box, p, " ")
        cx = int((p[1] + p[3]) / 2); cy = int((p[2] + p[4]) / 2)
        flag = ""
        if (line ~ /clickable="true"/) flag = flag "klik,"
        if (line ~ /enabled="false"/) flag = flag "mati,"
        if (line ~ /focused="true"/) flag = flag "fokus,"
        if (line ~ /checked="true"/) flag = flag "terpilih,"
        if (line ~ /scrollable="true"/) flag = flag "bisa-scroll,"
        if (line ~ /password="true"/) flag = flag "sandi,"
        sub(/,$/, "", flag)
        printf "%s\t%s\t%d,%d\t%s\n", cls, label, cx, cy, (flag == "" ? "-" : flag)
    }'
}

find_xy() {
    compact | awk -F'\t' -v want="$1" '
    BEGIN { want = tolower(want) }
    {
        key = tolower($2)
        if (key == want && !found) { print $3; found = 1; exit }
        if (best == "" && index(key, want) > 0) best = $3
    }
    END { if (!found && best != "") print best }'
}

cmd="${1:-}"
[ $# -gt 0 ] && shift

case "$cmd" in
    describe)
        limit="${1:-60}"
        info=$(rpc '[]' deviceInfo)
        pkg=$(printf '%s' "$info" | sed -n 's/.*"currentPackageName":"\([^"]*\)".*/\1/p')
        w=$(printf '%s' "$info" | sed -n 's/.*"displayWidth":\([0-9]*\).*/\1/p')
        h=$(printf '%s' "$info" | sed -n 's/.*"displayHeight":\([0-9]*\).*/\1/p')
        echo "app     : ${pkg:-?}"
        echo "layar   : ${w:-?}x${h:-?}"
        echo "keyboard: $(dumpsys input_method 2>/dev/null | grep -o 'mInputShown=[a-z]*' | head -1)"
        dump_xml || { echo "dump gagal"; exit 1; }
        echo "--- elemen (role | teks | koordinat | status) ---"
        compact | head -n "$limit"
        ;;
    dump)
        dump_xml || { echo "dump gagal"; exit 1; }
        compact | head -n "${1:-80}"
        ;;
    tap)
        want="${1:-}"
        [ -n "$want" ] || { echo "pemakaian: tap <text> [limit]"; exit 2; }
        dump_xml || { echo "dump gagal"; exit 1; }
        xy=$(find_xy "$want")
        if [ -z "$xy" ]; then
            echo "tidak ketemu: $want"
            compact | head -n 20
            exit 1
        fi
        rpc "[${xy%,*},${xy#*,}]" click >/dev/null
        sleep 0.3
        dump_xml && compact | head -n "${2:-40}"
        ;;
    tapby)
        rpc "[{\"text\":\"${1:?text}\"}]" click
        ;;
    tapxy)
        rpc "[${1:?x},${2:?y}]" click
        ;;
    swipe)
        rpc "[${1:?x1},${2:?y1},${3:?x2},${4:?y2},${5:-30}]" swipe
        ;;
    type)
        rpc "[{\"className\":\"android.widget.EditText\"},\"${1:-}\"]" setText >/dev/null
        ;;
    key)
        rpc "[\"${1:?back}\"]" pressKey >/dev/null
        ;;
    open)
        monkey -p "${1:?package}" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
        ;;
    wait)
        sleep "$(awk -v ms="${1:-500}" 'BEGIN { printf "%.3f", ms / 1000 }')"
        ;;
    shot)
        rpc "[\"${1:-$DUMP_DIR/shot.png}\",1.0,50]" takeScreenshot
        ;;
    win)
        rpc '[]' deviceInfo | sed -n 's/.*"currentPackageName":"\([^"]*\)".*/\1/p'
        ;;
    ping)
        curl -s -m 5 "http://127.0.0.1:9008/ping"
        ;;
    *)
        echo "phone.sh: describe|dump|tap|tapby|tapxy|swipe|type|key|open|wait|shot|win|ping"
        exit 2
        ;;
esac
