#!/bin/bash
# netns-ipsec-lab.sh — 完全自包含的单机双 netns IPsec 测试环境
#
# 认证方式：ECDSA 证书（moon / sun），CA 为 strongswanCert.pem
#
# 隔离策略（全部在 mount namespace 内完成，不影响宿主机）：
#   1) bind mount 实例的 strongswan.conf 到 $STRONGSWAN_DIR/etc/strongswan.conf
#   2) bind mount 实例的 run 目录到 /run（隔离 PID 文件路径）
#   3) vici socket 通过 strongswan.conf 配置成 unix://<abs-path>
#
# 用法：
#   sudo ./netns-ipsec-lab.sh up
#   sudo ./netns-ipsec-lab.sh start
#   sudo ./netns-ipsec-lab.sh status
#   sudo ./netns-ipsec-lab.sh swanctl a --load-all
#   sudo ./netns-ipsec-lab.sh swanctl a --initiate --child net
#   sudo ./netns-ipsec-lab.sh log a
#   sudo ./netns-ipsec-lab.sh down

set -euo pipefail

# ============================================================
# 路径配置
# ============================================================
BASE_DIR="/home/xk/test/ipsec"
STRONGSWAN_DIR="$BASE_DIR/strongswan"
LAB_DIR="$BASE_DIR/lab"
CERTS_DIR="$LAB_DIR/certs"
CHARON_BIN="$STRONGSWAN_DIR/libexec/ipsec/charon"
SWANCTL_BIN="$STRONGSWAN_DIR/sbin/swanctl"
STRONGSWAN_CONF="$STRONGSWAN_DIR/etc/strongswan.conf"

# ============================================================
# 证书元数据
# ------------------------------------------------------------
# 下面两个 DN 必须和证书里的 subject 或 SAN 匹配，否则 swanctl 加载
# 连接时会报 "no matching peer config"。用下面命令查看你实际证书的 DN：
#   openssl x509 -in moonCert.pem -noout -subject -ext subjectAltName
# ============================================================
DN_A="C=CH, O=strongswan, CN=moon.strongswan.org"
DN_B="C=CH, O=strongswan, CN=sun.strongswan.org"
CERT_A="moonCert.pem"
KEY_A="moonKey.pem"
CERT_B="sunCert.pem"
KEY_B="sunKey.pem"
CA_CERT="strongswanCert.pem"

# ============================================================
# 网络拓扑
# ============================================================
NETNS_A="ipsec-a"
NETNS_B="ipsec-b"
VETH_A="veth-a"
VETH_B="veth-b"
IP_A_CIDR="192.0.2.1/30"
IP_B_CIDR="192.0.2.2/30"
IP_A="192.0.2.1"
IP_B="192.0.2.2"

# ============================================================
# 辅助函数
# ============================================================
log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "需要 root，请使用 sudo"; }

side_ns()  { case "$1" in a) echo "$NETNS_A";; b) echo "$NETNS_B";; *) die "side 必须 a 或 b";; esac; }
side_dir() { echo "$LAB_DIR/$1"; }
side_ip()  { case "$1" in a) echo "$IP_A";; b) echo "$IP_B";; esac; }
side_cidr() { case "$1" in a) echo "$IP_A_CIDR";; b) echo "$IP_B_CIDR";; esac; }
other()    { [[ "$1" == a ]] && echo b || echo a; }
side_dn()  { case "$1" in a) echo "$DN_A";; b) echo "$DN_B";; esac; }
side_cert() { case "$1" in a) echo "$CERT_A";; b) echo "$CERT_B";; esac; }
side_key()  { case "$1" in a) echo "$KEY_A";; b) echo "$KEY_B";; esac; }

instance_pid() {
    local s="$1"
    local pf; pf="$(side_dir "$s")/run/charon.pid"
    [[ -f "$pf" ]] || { echo ""; return; }
    local p; p=$(cat "$pf" 2>/dev/null || echo "")
    if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then echo "$p"; else echo ""; fi
}

# ============================================================
# 目录与配置准备
# ============================================================
prepare_dirs() {
    mkdir -p "$LAB_DIR/log"

    for s in a b; do
        local d; d="$(side_dir "$s")"
        mkdir -p "$d/run"
        # swanctl 期望的标准目录（缺一不可，否则加载时刷屏报错）
        mkdir -p "$d"/{x509,x509ca,x509ocsp,x509aa,x509ac,x509crl}
        mkdir -p "$d"/{pubkey,private,rsa,ecdsa,pkcs8,pkcs12}
    done

    mkdir -p "$STRONGSWAN_DIR/etc"
    touch "$STRONGSWAN_CONF"

    # 检查证书是否齐全
    local missing=0
    for f in "$CA_CERT" "$CERT_A" "$KEY_A" "$CERT_B" "$KEY_B"; do
        [[ -f "$CERTS_DIR/$f" ]] || { log "  ✗ 缺少证书: $CERTS_DIR/$f"; missing=1; }
    done
    [[ $missing -eq 0 ]] || die "请把证书放到 $CERTS_DIR/ 后重试"
}

link_certs() {
    for s in a b; do
        local d; d="$(side_dir "$s")"
        local cert; cert="$(side_cert "$s")"
        local key;  key="$(side_key "$s")"

        # CA 证书 -> x509ca/
        ln -sf "$CERTS_DIR/$CA_CERT" "$d/x509ca/$CA_CERT"

        # 本端实体证书 -> x509/
        ln -sf "$CERTS_DIR/$cert" "$d/x509/$cert"

        # 本端私钥 -> private/
        ln -sf "$CERTS_DIR/$key" "$d/private/$key"

        # 为了 swanctl 用强类型加载，也在 ecdsa/ 放一份软链
        ln -sf "$CERTS_DIR/$key" "$d/ecdsa/$key"
    done
}

write_configs() {
    for s in a b; do
        local d; d="$(side_dir "$s")"
        local ns; ns="$(side_ns "$s")"
        local peer; peer="$(other "$s")"
        local my_dn; my_dn="$(side_dn "$s")"
        local peer_dn; peer_dn="$(side_dn "$peer")"
        local my_cert; my_cert="$(side_cert "$s")"

        cat > "$d/strongswan.conf" <<EOF
# strongswan.conf — side $s (netns $ns)
charon {
    plugins {
        vici {
            socket = unix://$d/run/charon.vici
        }
    }
    filelog {
        charon {
            path        = $LAB_DIR/log/$s.log
            time_format = %b %e %T
            ike_name    = yes
            append      = no
            default     = 2
            ike         = 3
            cfg         = 3
            knl         = 2
            chd         = 2
            flush_line  = yes
        }
    }
}
EOF

        # swanctl.conf —— IKEv1 + ECDSA 证书
        cat > "$d/swanctl.conf" <<EOF
# swanctl.conf — side $s (netns $ns) — IKEv1
# 本端 IP: $(side_ip $s)   对端 IP: $(side_ip $peer)
# 本端 DN: $my_dn
# 对端 DN: $peer_dn
#
# IKEv1 说明：
#   - version = 1
#   - 阶段1 proposals 中 PRF 与完整性算法合并，不必单列 prfxxx
#   - 阶段2 用 esp_proposals
#   - IKEv1 默认 main mode；如需 aggressive mode 加 aggressive = yes

connections {
    net {
        version = 1

        local_addrs  = $(side_ip $s)
        remote_addrs = $(side_ip $peer)

        # 阶段1 IKE 提议：加密-完整性-DH组
        proposals = aes256-sha256-ecp256

        local {
            auth = pubkey
            certs = $my_cert
            id = "$my_dn"
        }
        remote {
            auth = pubkey
            id = "$peer_dn"
        }

        children {
            net {
                local_ts  = 0.0.0.0/0
                remote_ts = 0.0.0.0/0
                # 阶段2 ESP 提议：加密-完整性-DH组（可选 PFS）
                esp_proposals = aes256-sha256-ecp256
                start_action = trap
            }
        }
    }
}
EOF
    done
}

# ============================================================
# netns 与 veth
# ============================================================
setup_netns() {
    log "=== 创建 netns ==="
    for ns in "$NETNS_A" "$NETNS_B"; do
        if ip netns list | grep -qw "$ns"; then
            log "  $ns 已存在，跳过"
        else
            ip netns add "$ns"
            log "  已创建 $ns"
        fi
        ip netns exec "$ns" ip link set lo up
    done

    log "=== 创建 veth 对 ==="
    if ip link show "$VETH_A" &>/dev/null; then
        log "  veth 对已存在，跳过"
    else
        ip link add "$VETH_A" netns "$NETNS_A" type veth peer name "$VETH_B" netns "$NETNS_B"
        log "  已创建 $VETH_A <-> $VETH_B"
    fi

    log "=== 配置 IP ==="
    ip netns exec "$NETNS_A" ip addr add "$(side_cidr a)" dev "$VETH_A" 2>/dev/null || true
    ip netns exec "$NETNS_A" ip link set "$VETH_A" up
    ip netns exec "$NETNS_B" ip addr add "$(side_cidr b)" dev "$VETH_B" 2>/dev/null || true
    ip netns exec "$NETNS_B" ip link set "$VETH_B" up
    log "  A: $(side_cidr a)，B: $(side_cidr b)"
}

teardown_netns() {
    for ns in "$NETNS_A" "$NETNS_B"; do
        if ip netns list | grep -qw "$ns"; then
            ip netns del "$ns"
            log "  已删除 $ns"
        fi
    done
}

# ============================================================
# charon 生命周期
# ============================================================
start_charon() {
    prepare_dirs
    link_certs
    write_configs

    for s in a b; do
        local d; d="$(side_dir "$s")"
        local ns; ns="$(side_ns "$s")"
        local logfile="$LAB_DIR/log/$s.log"

        if [[ -n "$(instance_pid "$s")" ]]; then
            log "  charon-$s 已在运行（PID $(instance_pid "$s")）"
            continue
        fi

        ip netns list | grep -qw "$ns" || die "netns $ns 不存在，先运行 '$0 up'"
        [[ -x "$CHARON_BIN" ]] || die "charon 二进制不存在或不可执行: $CHARON_BIN"

        rm -rf "$d/run"
        mkdir -p "$d/run"

        log "  启动 charon-$s（netns $ns）"
        : > "$logfile"

        ip netns exec "$ns" unshare --mount --propagation private bash -c "
            mount --bind '$d/strongswan.conf' '$STRONGSWAN_CONF'
            mount --bind '$d/run' /run
            exec '$CHARON_BIN'
        " >>"$logfile" 2>&1 &
    done

    sleep 3
    for s in a b; do
        local d; d="$(side_dir "$s")"
        local pid; pid="$(instance_pid "$s")"
        if [[ -n "$pid" ]] && [[ -S "$d/run/charon.vici" ]]; then
            log "  ✓ charon-$s 运行中（PID $pid）"
        else
            log "  ✗ charon-$s 未正常启动"
            echo "      run 目录内容:"
            ls -la "$d/run" 2>/dev/null | sed 's/^/        /'
            echo "      最近日志:"
            tail -8 "$LAB_DIR/log/$s.log" 2>/dev/null | sed 's/^/        /'
        fi
    done
}

stop_charon() {
    for s in a b; do
        local d; d="$(side_dir "$s")"
        local pid; pid="$(instance_pid "$s")"
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            log "  已停止 charon-$s（PID $pid）"
        fi
    done

    for p in $(pgrep -x charon 2>/dev/null || true); do
        local exe; exe=$(readlink /proc/"$p"/exe 2>/dev/null || echo "")
        if [[ "$exe" == "$CHARON_BIN" ]]; then
            kill "$p" 2>/dev/null || true
            log "  兜底清理残留 charon（PID $p）"
        fi
    done

    for s in a b; do
        rm -f "$(side_dir "$s")/run/charon.pid"
        rm -f "$(side_dir "$s")/run/charon.vici"
    done
    sleep 1
}

# ============================================================
# swanctl 包装
# ============================================================
run_swanctl() {
    local s="$1"; shift
    local ns; ns="$(side_ns "$s")"
    local d; d="$(side_dir "$s")"
    local uri="unix://$d/run/charon.vici"

    [[ -x "$SWANCTL_BIN" ]] || die "swanctl 不存在: $SWANCTL_BIN"
    [[ -S "$d/run/charon.vici" ]] || die "VICI socket 不存在: $d/run/charon.vici（charon 起来了吗？）"

    ip netns exec "$ns" env SWANCTL_DIR="$d" \
        "$SWANCTL_BIN" --uri "$uri" "$@"
}

# ============================================================
# 状态
# ============================================================
show_status() {
    for s in a b; do
        local ns; ns="$(side_ns "$s")"
        local d; d="$(side_dir "$s")"
        echo ""
        log "================= side $s (netns $ns) ================="
        if ! ip netns list | grep -qw "$ns"; then
            log "  netns 不存在"
            continue
        fi

        echo "  --- 接口 ---"
        ip netns exec "$ns" ip -brief addr 2>/dev/null | sed 's/^/    /'

        echo "  --- charon PID ---"
        if [[ -f "$d/run/charon.pid" ]]; then
            echo "    $(cat "$d/run/charon.pid")  ($d/run/charon.pid)"
        else
            echo "    （无 PID 文件）"
        fi

        echo "  --- VICI socket ---"
        [[ -S "$d/run/charon.vici" ]] && ls -l "$d/run/charon.vici" | sed 's/^/    /' || echo "    （无 socket）"

        echo "  --- XFRM State ---"
        ip netns exec "$ns" ip xfrm state 2>/dev/null | sed 's/^/    /' || true

        echo "  --- XFRM Policy ---"
        ip netns exec "$ns" ip xfrm policy 2>/dev/null | sed 's/^/    /' || true
    done
}

# ============================================================
# 主入口
# ============================================================
case "${1:-}" in
    up)
        need_root
        prepare_dirs
        link_certs
        write_configs
        setup_netns
        echo ""
        log "环境就绪。下一步："
        log "  sudo $0 start"
        log "  sudo $0 swanctl a --load-all"
        log "  sudo $0 swanctl b --load-all"
        log "  sudo $0 swanctl a --initiate --child net"
        ;;
    down)
        need_root
        stop_charon
        teardown_netns
        log "环境已清理（$LAB_DIR 保留，可手动删除）"
        ;;
    start)
        need_root; start_charon
        ;;
    stop)
        need_root; stop_charon
        ;;
    restart)
        need_root; stop_charon; start_charon
        ;;
    status)
        need_root; show_status
        ;;
    swanctl)
        need_root
        s="${2:-}"
        [[ "$s" == "a" || "$s" == "b" ]] || die "用法: $0 swanctl {a|b} <swanctl 参数>"
        shift 2
        run_swanctl "$s" "$@"
        ;;
    log)
        s="${2:-}"
        [[ -f "$LAB_DIR/log/$s.log" ]] || die "日志不存在: $LAB_DIR/log/$s.log"
        tail -f "$LAB_DIR/log/$s.log"
        ;;
    shell)
        need_root
        s="${2:-}"
        ns="$(side_ns "$s")"
        exec ip netns exec "$ns" bash
        ;;
    *)
        cat <<EOF
用法: $0 <命令> [参数]

命令:
  up                       创建 netns + veth + 分发证书 + 生成配置
  down                     停止 charon 并删除 netns
  start                    后台启动两个 charon 实例
  stop                     停止两个 charon
  restart                  stop + start
  status                   查看接口、进程、XFRM state/policy
  swanctl {a|b} <args>     在指定 netns 中运行 swanctl
  log {a|b}                tail 指定端 charon 日志
  shell {a|b}              进入指定 netns 的 bash
EOF
        exit 1
        ;;
esac
