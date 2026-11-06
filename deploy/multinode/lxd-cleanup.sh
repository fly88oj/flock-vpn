#!/usr/bin/env bash
# lxd-cleanup.sh —— 多机实测收尾（jowency 侧，经 ssh 执行）：
#   bash lxd-cleanup.sh            # 全清：flock-* 容器（含 proxy device）+ frps 进程
#                                  #        + ~/flock-mn（二进制/集群材料/临时文件）
#   bash lxd-cleanup.sh --keep-files   # 只删容器与 frps（保留 ~/flock-mn 复用材料）
#
# 边界：只删 flock-* 前缀容器（proxy device 随容器消亡）；既有容器
# （dmgvm/krymux-*/l2ctest/uesktop-ui-audit 等）零触碰。退出码：恒 0（缺项即已净）。

set -u

KEEP_FILES=0
[ "${1:-}" = "--keep-files" ] && KEEP_FILES=1

echo "== flock-* 容器 =="
mapfile -t ct < <(lxc list flock- -c n --format csv 2>/dev/null)
if [ "${#ct[@]}" -gt 0 ] && [ -n "${ct[0]}" ]; then
    lxc delete --force "${ct[@]}"
    echo "已删：${ct[*]}"
else
    echo "（无）"
fi

echo "== frps 宿主进程（lxd-setup.sh 场景二启动）=="
if pkill -f 'flock-mn/bin/frps' 2>/dev/null; then
    echo "已停 frps"
else
    echo "（未在跑）"
fi

if [ "$KEEP_FILES" = 0 ]; then
    echo "== ~/flock-mn（二进制/集群材料/日志/临时文件）=="
    rm -rf ~/flock-mn
    echo "已收走"
else
    echo "--keep-files：~/flock-mn 保留"
fi

echo "清理完成。剩余 flock-* 容器：$(lxc list flock- -c n --format csv 2>/dev/null | tr '\n' ' ')"
