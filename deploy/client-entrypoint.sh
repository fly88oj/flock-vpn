#!/bin/sh
# M3 客户端入口（docs/design.md §7-M3）。
#
# 编排序（deploy/m3_assert.sh 驱动）：
#   1. 客户端 `gen-keys`（生成/复用设备密钥并打印公钥）；
#   2. 服务端 `device-add`（注册设备 + 分 VIP）与 `invite`（签发 v3 邀请）；
#   3. 客户端 `invite <file>`（钉扎根公钥 + 存根签目录）+ 写 vip 文件；
#   4. `touch /var/lib/flock/ready` 后 `docker compose restart client`
#      ⇒ 本入口 exec 客户端主进程（日志进 `docker compose logs client`，A9 grep 面）。
set -e
STATE=/var/lib/flock

if [ -f "$STATE/ready" ]; then
    echo "flock-client: state ready; starting (config /etc/flock/client.toml)"
    exec flock-client --config /etc/flock/client.toml
fi

echo "flock-client: awaiting bootstrap (run deploy/m3_assert.sh)..."
exec sleep infinity
