ostlock-RMX3031
GhostLock (CVE-2026-43499) exploit for RMX3031（realme GT Neo / MT6893）— stage1  Linux 内核 4.14.186+   ColorOS 11

boot.bin 可以用 [mtkclient](https://github.com/bkerler/mtkclient)  或者 [ OTA-Pulse ](https://github.com/RemuruSama/OTA-Pulse) 提取 

已知致命 bug root 后屏幕无响应, 只能电脑 adb reboot重启恢复

adb reboot 没用可以 通过 root 守护写内核节点（绕开 init/SELinux）

`adb shell "cd /data/local/tmp && ./stage1 --su 'echo 1 > /proc/sys/kernel/sysrq; echo b > /proc/sysrq-trigger'"`
