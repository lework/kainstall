#!/usr/bin/env bash
###################################################################
#Script Name    : kainstall-debian.sh
#Description    : Install kubernetes cluster using kubeadm.
#Create Date    : 2021-04-18
#Author         : lework
#Email          : lework@yeah.net
###################################################################


[[ -n $DEBUG ]] && set -x
set -o errtrace         # Make sure any error trap is inherited
set -o nounset          # Disallow expansion of unset variables
set -o pipefail         # Use last non-zero exit code in a pipeline


######################################################################################################
# environment configuration
######################################################################################################

# 版本
KUBE_VERSION="${KUBE_VERSION:-latest}"
FLANNEL_VERSION="${FLANNEL_VERSION:-0.15.1}"
METRICS_SERVER_VERSION="${METRICS_SERVER_VERSION:-0.5.2}"
INGRESS_NGINX="${INGRESS_NGINX:-1.1.0}"
TRAEFIK_VERSION="${TRAEFIK_VERSION:-2.5.6}"
CALICO_VERSION="${CALICO_VERSION:-3.21.2}"
CILIUM_VERSION="${CILIUM_VERSION:-1.9.11}"
KUBE_PROMETHEUS_VERSION="${KUBE_PROMETHEUS_VERSION:-0.9.0}"
ELASTICSEARCH_VERSION="${ELASTICSEARCH_VERSION:-7.16.2}"
ROOK_VERSION="${ROOK_VERSION:-1.8.1}"
LONGHORN_VERSION="${LONGHORN_VERSION:-1.2.3}"
KUBERNETES_DASHBOARD_VERSION="${KUBERNETES_DASHBOARD_VERSION:-2.4.0}"
KUBESPHERE_VERSION="${KUBESPHERE_VERSION:-3.2.1}"

# 集群配置
KUBE_DNSDOMAIN="${KUBE_DNSDOMAIN:-cluster.local}"
KUBE_APISERVER="${KUBE_APISERVER:-apiserver.$KUBE_DNSDOMAIN}"
KUBE_POD_SUBNET="${KUBE_POD_SUBNET:-10.244.0.0/16}"
KUBE_SERVICE_SUBNET="${KUBE_SERVICE_SUBNET:-10.96.0.0/16}"
KUBE_IMAGE_REPO="${KUBE_IMAGE_REPO:-registry.cn-hangzhou.aliyuncs.com/kainstall}"
KUBE_NETWORK="${KUBE_NETWORK:-flannel}"
KUBE_INGRESS="${KUBE_INGRESS:-nginx}"
KUBE_MONITOR="${KUBE_MONITOR:-prometheus}"
KUBE_STORAGE="${KUBE_STORAGE:-rook}"
KUBE_LOG="${KUBE_LOG:-elasticsearch}"
KUBE_UI="${KUBE_UI:-dashboard}"
KUBE_ADDON="${KUBE_ADDON:-metrics-server}"
KUBE_FLANNEL_TYPE="${KUBE_FLANNEL_TYPE:-vxlan}"
KUBE_CRI="${KUBE_CRI:-docker}"
KUBE_CRI_VERSION="${KUBE_CRI_VERSION:-latest}"
KUBE_CRI_ENDPOINT="${KUBE_CRI_ENDPOINT:-/var/run/dockershim.sock}"

# 定义的master和worker节点地址，以逗号分隔
MASTER_NODES="${MASTER_NODES:-}"
WORKER_NODES="${WORKER_NODES:-}"

# 定义在哪个节点上进行设置
MGMT_NODE="${MGMT_NODE:-127.0.0.1}"

# 节点的连接信息
SSH_USER="${SSH_USER:-root}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
SSH_PRIVATE_KEY="${SSH_PRIVATE_KEY:-}"
SSH_PORT="${SSH_PORT:-22}"
SUDO_USER="${SUDO_USER:-root}"

# 节点设置
HOSTNAME_PREFIX="${HOSTNAME_PREFIX:-k8s}"

# 脚本设置
TMP_DIR="$(rm -rf /tmp/kainstall* && mktemp -d -t kainstall.XXXXXXXXXX)"
LOG_FILE="${TMP_DIR}/kainstall.log"
SSH_OPTIONS="-o ConnectTimeout=600 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
ERROR_INFO="\n\033[31mERROR Summary: \033[0m\n  "
ACCESS_INFO="\n\033[32mACCESS Summary: \033[0m\n  "
COMMAND_OUTPUT=""
SCRIPT_PARAMETER="$*"
OFFLINE_DIR="/tmp/kainstall-offline-file/"
OFFLINE_FILE=""
OS_SUPPORT="debian9 debian10"
GITHUB_PROXY="${GITHUB_PROXY:-https://gh.lework.workers.dev/}"
GCR_PROXY="${GCR_PROXY:-k8sgcr.lework.workers.dev}"
SKIP_UPGRADE_PLAN=${SKIP_UPGRADE_PLAN:-false}
SKIP_SET_OS_REPO=${SKIP_SET_OS_REPO:-false}

trap trap::info 1 2 3 15 EXIT

######################################################################################################
# function
######################################################################################################

function trap::info() {
  # 信号处理
  
  [[ ${#ERROR_INFO} -gt 37 ]] && echo -e "$ERROR_INFO"
  [[ ${#ACCESS_INFO} -gt 38 ]] && echo -e "$ACCESS_INFO"
  [ -f "$LOG_FILE" ] && echo -e "\n\n  See detailed log >>> $LOG_FILE \n\n"
  trap '' EXIT
  exit
}


function log::error() {
  # 错误日志
  
  local item; item="[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[31mERROR:   \033[0m$*"
  ERROR_INFO="${ERROR_INFO}${item}\n  "
  echo -e "${item}" | tee -a "$LOG_FILE"
}


function log::info() {
  # 基础日志
  
  printf "[%s]: \033[32mINFO:    \033[0m%s\n" "$(date +'%Y-%m-%dT%H:%M:%S.%N%z')" "$*" | tee -a "$LOG_FILE"
}


function log::warning() {
  # 警告日志
  
  printf "[%s]: \033[33mWARNING: \033[0m%s\n" "$(date +'%Y-%m-%dT%H:%M:%S.%N%z')" "$*" | tee -a "$LOG_FILE"
}


function log::access() {
  # 访问信息
  
  ACCESS_INFO="${ACCESS_INFO}$*\n  "
  printf "[%s]: \033[32mINFO:    \033[0m%s\n" "$(date +'%Y-%m-%dT%H:%M:%S.%N%z')" "$*" | tee -a "$LOG_FILE"
}


function log::exec() {
  # 执行日志
  
  printf "[%s]: \033[34mEXEC:    \033[0m%s\n" "$(date +'%Y-%m-%dT%H:%M:%S.%N%z')" "$*" >> "$LOG_FILE"
}


function utils::version_to_number() {
  # 版本号转数字

  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }';
}


function utils::retry {
  # 重试

  local retries=$1
  shift

  local count=0
  until eval "$*"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))
    if [ "$count" -lt "$retries" ]; then
      echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
      sleep $wait
    else
      echo "Retry $count/$retries exited $exit, no more retries left."
      return $exit
    fi
  done
  return 0
}


function utils::quote() {
  # 转义引号

  # shellcheck disable=SC2046 
  if [ $(echo "$*" | tr -d "\n" | wc -c) -eq 0 ]; then
    echo "''"
  elif [ $(echo "$*" | tr -d "[a-z][A-Z][0-9]:,.=~_/\n-" | wc -c) -gt 0 ]; then
    printf "%s" "$*" | sed -e "1h;2,\$H;\$!d;g" -e "s/'/\'\"\'\"\'/g" | sed -e "1h;2,\$H;\$!d;g" -e "s/^/'/g" -e "s/$/'/g"
  else
    echo "$*"
  fi
}


function utils::download_file() {
  # 下载文件
  
  local url="$1"
  local dest="$2"
  local unzip_tag="${3:-1}"
  
  local dest_dirname; dest_dirname=$(dirname "$dest")
  local filename; filename=$(basename "$dest")
  
  log::info "[download]" "${filename}"
  command::exec "${MGMT_NODE}" "
    set -e
    if [ ! -f \"${dest}\" ]; then
      [ ! -d \"${dest_dirname}\" ] && mkdir -pv \"${dest_dirname}\" 
      wget --timeout=10 --waitretry=3 --tries=5 --retry-connrefused \"${url}\" -O \"${dest}\"
      if [[ \"${unzip_tag}\" == \"unzip\" ]]; then
        command -v unzip 2>/dev/null || apt-get install -y unzip
        unzip -o \"${dest}\" -d \"${dest_dirname}\"
      fi
    else
      echo \"${dest} is exists!\"
    fi
  "
  local status="$?"
  check::exit_code "$status" "download" "${filename}"
  return "$status"
}


function utils::is_element_in_array() {
  # 判断是否在数组中存在元素

  local -r element="${1}"
  local -r array=("${@:2}")

  local walker=''

  for walker in "${array[@]}"
  do
    [[ "${walker}" = "${element}" ]] && return 0
  done

  return 1
}


function command::exec() {
  # 执行命令

  local host=${1:-}
  shift
  local command="$*"
  
  if [[ "${SUDO_TAG:-}" == "1" ]]; then
    sudo_options="sudo -H -n -u ${SUDO_USER}"
  
    if [[ "${SUDO_PASSWORD:-}" != "" ]]; then
       sudo_options="${sudo_options// -n/} -p \"\" -S <<< \"${SUDO_PASSWORD}\""
    fi
    command="$sudo_options bash -c $(utils::quote "$command")"
  fi
  
  command="$(utils::quote "$command")"
  
  if [[ "${host}" == "127.0.0.1" ]]; then
    # 本地执行
    log::exec "[command]" "bash -c $(printf "%s" "${command//${SUDO_PASSWORD:-}/zzzzzz}")"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval bash -c "${command}" 2>> "$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  else
    # 远程执行
    local ssh_cmd="ssh"
    if [[ "${SSH_PASSWORD}" != "" ]]; then
      ssh_cmd="sshpass -p \"${SSH_PASSWORD}\" ${ssh_cmd}"
    elif [[ "$SSH_PRIVATE_KEY" != "" ]]; then
      [ -f "${SSH_PRIVATE_KEY}" ] || { log::error "[exec]" "ssh private_key:${SSH_PRIVATE_KEY} not found."; exit 1; }
      ssh_cmd="${ssh_cmd} -i $SSH_PRIVATE_KEY"
    fi
    log::exec "[command]" "${ssh_cmd//${SSH_PASSWORD:-}/zzzzzz} ${SSH_OPTIONS} ${SSH_USER}@${host} -p ${SSH_PORT} bash -c $(printf "%s" "${command//${SUDO_PASSWORD:-}/zzzzzz}")"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval "${ssh_cmd} ${SSH_OPTIONS} ${SSH_USER}@${host} -p ${SSH_PORT}" bash -c '"${command}"' 2>> "$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  fi
  return $status
}


function command::scp() {
  # 拷贝文件

  local host=${1:-}
  local src=${2:-}
  local dest=${3:-/tmp/}
  
  if [[ "${host}" == "127.0.0.1" ]]; then
    local command="cp -rf ${src} ${dest}"
    log::exec "[command]" "bash -c \"${command}\""
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(bash -c "${command}" 2>> "$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  else
    local scp_cmd="scp"
    if [[ "${SSH_PASSWORD}" != "" ]]; then
      scp_cmd="sshpass -p \"${SSH_PASSWORD}\" ${scp_cmd}"
    elif [[ "$SSH_PRIVATE_KEY" != "" ]]; then
      [ -f "${SSH_PRIVATE_KEY}" ] || { log::error "[exec]" "ssh private_key:${SSH_PRIVATE_KEY} not found."; exit 1; }
      scp_cmd="${scp_cmd} -i $SSH_PRIVATE_KEY"
    fi
    log::exec "[command]" "${scp_cmd} ${SSH_OPTIONS} -P ${SSH_PORT} -r ${src} ${SSH_USER}@${host}:${dest}" >> "$LOG_FILE"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval "${scp_cmd} ${SSH_OPTIONS} -P ${SSH_PORT} -r ${src} ${SSH_USER}@${host}:${dest}" 2>> "$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  fi
  return $status
}


function script::init_node() {
  # 节点初始化脚本
  
  # clean
  sed -i -e "/$KUBE_APISERVER/d" -e '/-worker-/d' -e '/-master-/d' /etc/hosts
  sed -i '/## Kainstall managed start/,/## Kainstall managed end/d' /etc/security/limits.conf /etc/systemd/system.conf /etc/bash.bashrc /etc/audit/rules.d/audit.rules  

  # Disable selinux
  sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config
  setenforce 0
  
  # Disable swap
  swapoff -a && sysctl -w vm.swappiness=0
  sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab

  # Disable firewalld
  for target in firewalld python-firewall firewalld-filesystem iptables; do
    systemctl stop $target &>/dev/null || true
    systemctl disable $target &>/dev/null || true
  done

  # repo
  local codename; codename="$(dpkg --status tzdata|grep Provides|cut -f2 -d'-')"
  [[ "${SKIP_SET_OS_REPO,,}" == "false" ]] && cp -fv /etc/apt/sources.list{,.bak}
  [[ "${SKIP_SET_OS_REPO,,}" == "false" ]] && cat << EOF > /etc/apt/sources.list
deb http://mirrors.aliyun.com/debian/ ${codename} main contrib non-free
deb-src http://mirrors.aliyun.com/debian/  ${codename} main contrib non-free

deb http://mirrors.aliyun.com/debian/  ${codename}-updates main contrib non-free
deb-src http://mirrors.aliyun.com/debian/  ${codename}-updates main contrib non-free

deb http://mirrors.aliyun.com/debian-security/  ${codename}/updates main contrib non-free
deb-src http://mirrors.aliyun.com/debian-security/  ${codename}/updates main contrib non-free
EOF
  apt update

  echo -e '#!/bin/sh\nexit 101' | install -m 755 /dev/stdin /usr/sbin/policy-rc.d

  systemctl mask apt-daily.service apt-daily-upgrade.service
  systemctl stop apt-daily.timer apt-daily-upgrade.timer
  systemctl disable apt-daily.timer apt-daily-upgrade.timer
  systemctl kill --kill-who=all apt-daily.service

cat << EOF > /etc/apt/apt.conf.d/10cloudinit-disable
APT::Periodic::Enable "0";
// undo what's in 20auto-upgrade
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

  # Change limits
  [ ! -f /etc/security/limits.conf_bak ] && cp /etc/security/limits.conf{,_bak}
  cat << EOF >> /etc/security/limits.conf
## Kainstall managed start
root soft nofile 655360
root hard nofile 655360
root soft nproc 655360
root hard nproc 655360
root soft core unlimited
root hard core unlimited

* soft nofile 655360
* hard nofile 655360
* soft nproc 655360
* hard nproc 655360
* soft core unlimited
* hard core unlimited
## Kainstall managed end
EOF

  [ -f /etc/security/limits.d/20-nproc.conf ] && sed -i 's#4096#655360#g' /etc/security/limits.d/20-nproc.conf
  cat << EOF >> /etc/systemd/system.conf
## Kainstall managed start
DefaultLimitCORE=infinity
DefaultLimitNOFILE=655360
DefaultLimitNPROC=655360
DefaultTasksMax=75%
## Kainstall managed end
EOF

   # Change sysctl
   cat << EOF >  /etc/sysctl.d/99-kube.conf
# https://www.kernel.org/doc/Documentation/sysctl/
#############################################################################################
# 调整虚拟内存
#############################################################################################

# Default: 30
# 0 - 任何情况下都不使用swap。
# 1 - 除非内存不足（OOM），否则不使用swap。
vm.swappiness = 0

# 内存分配策略
#0 - 表示内核将检查是否有足够的可用内存供应用进程使用；如果有足够的可用内存，内存申请允许；否则，内存申请失败，并把错误返回给应用进程。
#1 - 表示内核允许分配所有的物理内存，而不管当前的内存状态如何。
#2 - 表示内核允许分配超过所有物理内存和交换空间总和的内存
vm.overcommit_memory=1

# OOM时处理
# 1关闭，等于0时，表示当内存耗尽时，内核会触发OOM killer杀掉最耗内存的进程。
vm.panic_on_oom=0

# vm.dirty_background_ratio 用于调整内核如何处理必须刷新到磁盘的脏页。
# Default value is 10.
# 该值是系统内存总量的百分比，在许多情况下将此值设置为5是合适的。
# 此设置不应设置为零。
vm.dirty_background_ratio = 5

# 内核强制同步操作将其刷新到磁盘之前允许的脏页总数
# 也可以通过更改 vm.dirty_ratio 的值（将其增加到默认值30以上（也占系统内存的百分比））来增加
# 推荐 vm.dirty_ratio 的值在60到80之间。
vm.dirty_ratio = 60

# vm.max_map_count 计算当前的内存映射文件数。
# mmap 限制（vm.max_map_count）的最小值是打开文件的ulimit数量（cat /proc/sys/fs/file-max）。
# 每128KB系统内存 map_count应该大约为1。 因此，在32GB系统上，max_map_count为262144。
# Default: 65530
vm.max_map_count = 2097152

#############################################################################################
# 调整文件
#############################################################################################

fs.may_detach_mounts = 1

# 增加文件句柄和inode缓存的大小，并限制核心转储。
fs.file-max = 2097152
fs.nr_open = 2097152
fs.suid_dumpable = 0

# 文件监控
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=524288
fs.inotify.max_queued_events=16384

#############################################################################################
# 调整网络设置
#############################################################################################

# 为每个套接字的发送和接收缓冲区分配的默认内存量。
net.core.wmem_default = 25165824
net.core.rmem_default = 25165824

# 为每个套接字的发送和接收缓冲区分配的最大内存量。
net.core.wmem_max = 25165824
net.core.rmem_max = 25165824

# 除了套接字设置外，发送和接收缓冲区的大小
# 必须使用net.ipv4.tcp_wmem和net.ipv4.tcp_rmem参数分别设置TCP套接字。
# 使用三个以空格分隔的整数设置这些整数，分别指定最小，默认和最大大小。
# 最大大小不能大于使用net.core.wmem_max和net.core.rmem_max为所有套接字指定的值。
# 合理的设置是最小4KiB，默认64KiB和最大2MiB缓冲区。
net.ipv4.tcp_wmem = 20480 12582912 25165824
net.ipv4.tcp_rmem = 20480 12582912 25165824

# 增加最大可分配的总缓冲区空间
# 以页为单位（4096字节）进行度量
net.ipv4.tcp_mem = 65536 25165824 262144
net.ipv4.udp_mem = 65536 25165824 262144

# 为每个套接字的发送和接收缓冲区分配的最小内存量。
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_rmem_min = 16384

# 启用TCP窗口缩放，客户端可以更有效地传输数据，并允许在代理方缓冲该数据。
net.ipv4.tcp_window_scaling = 1

# 提高同时接受连接数。
net.ipv4.tcp_max_syn_backlog = 10240

# 将net.core.netdev_max_backlog的值增加到大于默认值1000
# 可以帮助突发网络流量，特别是在使用数千兆位网络连接速度时，
# 通过允许更多的数据包排队等待内核处理它们。
net.core.netdev_max_backlog = 65536

# 增加选项内存缓冲区的最大数量
net.core.optmem_max = 25165824

# 被动TCP连接的SYNACK次数。
net.ipv4.tcp_synack_retries = 2

# 允许的本地端口范围。
net.ipv4.ip_local_port_range = 2048 65535

# 防止TCP时间等待
# Default: net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_rfc1337 = 1

# 减少tcp_fin_timeout连接的时间默认值
net.ipv4.tcp_fin_timeout = 15

# 积压套接字的最大数量。
# Default is 128.
net.core.somaxconn = 32768

# 打开syncookies以进行SYN洪水攻击保护。
net.ipv4.tcp_syncookies = 1

# 避免Smurf攻击
# 发送伪装的ICMP数据包，目的地址设为某个网络的广播地址，源地址设为要攻击的目的主机，
# 使所有收到此ICMP数据包的主机都将对目的主机发出一个回应，使被攻击主机在某一段时间内收到成千上万的数据包
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 为icmp错误消息打开保护
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 启用自动缩放窗口。
# 如果延迟证明合理，这将允许TCP缓冲区超过其通常的最大值64K。
net.ipv4.tcp_window_scaling = 1

# 打开并记录欺骗，源路由和重定向数据包
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 告诉内核有多少个未附加的TCP套接字维护用户文件句柄。 万一超过这个数字，
# 孤立的连接会立即重置，并显示警告。
# Default: net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_max_orphans = 65536

# 不要在关闭连接时缓存指标
net.ipv4.tcp_no_metrics_save = 1

# 启用RFC1323中定义的时间戳记：
# Default: net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_timestamps = 1

# 启用选择确认。
# Default: net.ipv4.tcp_sack = 1
net.ipv4.tcp_sack = 1

# 增加 tcp-time-wait 存储桶池大小，以防止简单的DOS攻击。
# net.ipv4.tcp_tw_recycle 已从Linux 4.12中删除。请改用net.ipv4.tcp_tw_reuse。
net.ipv4.tcp_max_tw_buckets = 14400
net.ipv4.tcp_tw_reuse = 1

# accept_source_route 选项使网络接口接受设置了严格源路由（SSR）或松散源路由（LSR）选项的数据包。
# 以下设置将丢弃设置了SSR或LSR选项的数据包。
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# 打开反向路径过滤
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 禁用ICMP重定向接受
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 禁止发送所有IPv4 ICMP重定向数据包。
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 开启IP转发.
net.ipv4.ip_forward = 1

# 禁止IPv6
net.ipv6.conf.lo.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# 要求iptables不对bridge的数据进行处理
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1

# arp缓存
# 存在于 ARP 高速缓存中的最少层数，如果少于这个数，垃圾收集器将不会运行。缺省值是 128
net.ipv4.neigh.default.gc_thresh1=2048
# 保存在 ARP 高速缓存中的最多的记录软限制。垃圾收集器在开始收集前，允许记录数超过这个数字 5 秒。缺省值是 512
net.ipv4.neigh.default.gc_thresh2=4096
# 保存在 ARP 高速缓存中的最多记录的硬限制，一旦高速缓存中的数目高于此，垃圾收集器将马上运行。缺省值是 1024
net.ipv4.neigh.default.gc_thresh3=8192

# 持久连接
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10

# conntrack表
net.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_buckets=262144
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=30
net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
net.netfilter.nf_conntrack_tcp_timeout_close_wait=15
net.netfilter.nf_conntrack_tcp_timeout_established=300

#############################################################################################
# 调整内核参数
#############################################################################################

# 地址空间布局随机化（ASLR）是一种用于操作系统的内存保护过程，可防止缓冲区溢出攻击。
# 这有助于确保与系统上正在运行的进程相关联的内存地址不可预测，
# 因此，与这些流程相关的缺陷或漏洞将更加难以利用。
# Accepted values: 0 = 关闭, 1 = 保守随机化, 2 = 完全随机化
kernel.randomize_va_space = 2

# 调高 PID 数量
kernel.pid_max = 65536
kernel.threads-max=30938

# coredump
kernel.core_pattern=core

# 决定了检测到soft lockup时是否自动panic，缺省值是0
kernel.softlockup_all_cpu_backtrace=1
kernel.softlockup_panic=1
EOF

  # history
  cat << EOF >> /etc/bash.bashrc
## Kainstall managed start
# history actions record，include action time, user, login ip
HISTFILESIZE=5000
HISTSIZE=5000
USER_IP=\$(who -u am i 2>/dev/null | awk '{print \$NF}' | sed -e 's/[()]//g')
if [ -z \$USER_IP ]
then
  USER_IP=\$(hostname -i)
fi
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S \$USER_IP:\$(whoami) "
export HISTFILESIZE HISTSIZE HISTTIMEFORMAT

# PS1
PS1='\[\033[0m\]\[\033[1;36m\][\u\[\033[0m\]@\[\033[1;32m\]\h\[\033[0m\] \[\033[1;31m\]\w\[\033[0m\]\[\033[1;36m\]]\[\033[33;1m\]\\$ \[\033[0m\]'
## Kainstall managed end
EOF

   # journal
   mkdir -p /var/log/journal /etc/systemd/journald.conf.d
   cat << EOF > /etc/systemd/journald.conf.d/99-prophet.conf
[Journal]
# 持久化保存到磁盘
Storage=persistent
# 压缩历史日志
Compress=yes
SyncIntervalSec=5m
RateLimitInterval=30s
RateLimitBurst=1000
# 最大占用空间 10G
SystemMaxUse=10G
# 单日志文件最大 200M
SystemMaxFileSize=200M
# 日志保存时间 3 周
MaxRetentionSec=3week
# 不将日志转发到 syslog
ForwardToSyslog=no
EOF

  # motd
  cat << EOF > /etc/profile.d/zz-ssh-login-info.sh
#!/bin/sh
#
# @Time    : 2020-02-04
# @Author  : lework
# @Desc    : ssh login banner

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
shopt -q login_shell && : || return 0
echo -e "\033[0;32m
 ██╗  ██╗ █████╗ ███████╗
 ██║ ██╔╝██╔══██╗██╔════╝
 █████╔╝ ╚█████╔╝███████╗
 ██╔═██╗ ██╔══██╗╚════██║
 ██║  ██╗╚█████╔╝███████║
 ╚═╝  ╚═╝ ╚════╝ ╚══════ by kainstall\033[0m"

# os
upSeconds="\$(cut -d. -f1 /proc/uptime)"
secs=\$((\${upSeconds}%60))
mins=\$((\${upSeconds}/60%60))
hours=\$((\${upSeconds}/3600%24))
days=\$((\${upSeconds}/86400))
UPTIME_INFO=\$(printf "%d days, %02dh %02dm %02ds" "\$days" "\$hours" "\$mins" "\$secs")

if [ -f /etc/redhat-release ] ; then
    PRETTY_NAME=\$(< /etc/redhat-release)

elif [ -f /etc/debian_version ]; then
   DIST_VER=\$(</etc/debian_version)
   PRETTY_NAME="\$(grep PRETTY_NAME /etc/os-release | sed -e 's/PRETTY_NAME=//g' -e  's/"//g') (\$DIST_VER)"

else
    PRETTY_NAME=\$(cat /etc/*-release | grep "PRETTY_NAME" | sed -e 's/PRETTY_NAME=//g' -e 's/"//g')
fi

if [[ -d "/system/app/" && -d "/system/priv-app" ]]; then
    model="\$(getprop ro.product.brand) \$(getprop ro.product.model)"

elif [[ -f /sys/devices/virtual/dmi/id/product_name ||
        -f /sys/devices/virtual/dmi/id/product_version ]]; then
    model="\$(< /sys/devices/virtual/dmi/id/product_name)"
    model+=" \$(< /sys/devices/virtual/dmi/id/product_version)"

elif [[ -f /sys/firmware/devicetree/base/model ]]; then
    model="\$(< /sys/firmware/devicetree/base/model)"

elif [[ -f /tmp/sysinfo/model ]]; then
    model="\$(< /tmp/sysinfo/model)"
fi

MODEL_INFO=\${model}
KERNEL=\$(uname -srmo)
USER_NUM=\$(who -u | wc -l)
RUNNING=\$(ps ax | wc -l | tr -d " ")

# disk
totaldisk=\$(df -h -x devtmpfs -x tmpfs -x debugfs -x aufs -x overlay --total 2>/dev/null | tail -1)
disktotal=\$(awk '{print \$2}' <<< "\${totaldisk}")
diskused=\$(awk '{print \$3}' <<< "\${totaldisk}")
diskusedper=\$(awk '{print \$5}' <<< "\${totaldisk}")
DISK_INFO="\033[0;33m\${diskused}\033[0m of \033[1;34m\${disktotal}\033[0m disk space used (\033[0;33m\${diskusedper}\033[0m)"

# cpu
cpu=\$(awk -F':' '/^model name/ {print \$2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//')
cpun=\$(grep -c '^processor' /proc/cpuinfo)
cpuc=\$(grep '^cpu cores' /proc/cpuinfo | tail -1 | awk '{print \$4}')
cpup=\$(grep '^physical id' /proc/cpuinfo | wc -l)
CPU_INFO="\${cpu} \${cpup}P \${cpuc}C \${cpun}L"

# get the load averages
read one five fifteen rest < /proc/loadavg
LOADAVG_INFO="\033[0;33m\${one}\033[0m / \${five} / \${fifteen} with \033[1;34m\$(( cpun*cpuc ))\033[0m core(s) at \033[1;34m\$(grep '^cpu MHz' /proc/cpuinfo | tail -1 | awk '{print \$4}')\033 MHz"

# mem
MEM_INFO="\$(cat /proc/meminfo | awk '/MemTotal:/{total=\$2/1024/1024;next} /MemAvailable:/{use=total-\$2/1024/1024; printf("\033[0;33m%.2fGiB\033[0m of \033[1;34m%.2fGiB\033[0m RAM used (\033[0;33m%.2f%%\033[0m)",use,total,(use/total)*100);}')"

# network
# extranet_ip=" and \$(curl -s ip.cip.cc)"
IP_INFO="\$(ip a | grep glo | awk '{print \$2}' | head -1 | cut -f1 -d/)\${extranet_ip:-}"

# Container info
CONTAINER_INFO="\$(sudo /usr/bin/crictl ps -a -o yaml 2> /dev/null | awk '/^  state: /{gsub("CONTAINER_", "", \$NF) ++S[\$NF]}END{for(m in S) printf "%s%s:%s ",substr(m,1,1),tolower(substr(m,2)),S[m]}')Images:\$(sudo /usr/bin/crictl images -q 2> /dev/null | wc -l)"

# info
echo -e "
 Information as of: \033[1;34m\$(date +"%Y-%m-%d %T")\033[0m
 
 \033[0;1;31mProduct\033[0m............: \${MODEL_INFO}
 \033[0;1;31mOS\033[0m.................: \${PRETTY_NAME}
 \033[0;1;31mKernel\033[0m.............: \${KERNEL}
 \033[0;1;31mCPU\033[0m................: \${CPU_INFO}

 \033[0;1;31mHostname\033[0m...........: \033[1;34m\$(hostname)\033[0m
 \033[0;1;31mIP Addresses\033[0m.......: \033[1;34m\${IP_INFO}\033[0m

 \033[0;1;31mUptime\033[0m.............: \033[0;33m\${UPTIME_INFO}\033[0m
 \033[0;1;31mMemory\033[0m.............: \${MEM_INFO}
 \033[0;1;31mLoad Averages\033[0m......: \${LOADAVG_INFO}
 \033[0;1;31mDisk Usage\033[0m.........: \${DISK_INFO} 

 \033[0;1;31mUsers online\033[0m.......: \033[1;34m\${USER_NUM}\033[0m
 \033[0;1;31mRunning Processes\033[0m..: \033[1;34m\${RUNNING}\033[0m
 \033[0;1;31mContainer Info\033[0m.....: \${CONTAINER_INFO}
"
EOF

  chmod +x /etc/profile.d/zz-ssh-login-info.sh
  echo 'ALL ALL=(ALL) NOPASSWD:/usr/bin/crictl' > /etc/sudoers.d/crictl

  # time sync
  ntpd --help >/dev/null 2>&1 && apt-get remove -y ntp
  [[ "${OFFLINE_TAG:-}" != "1" ]] && apt-get install -y chrony 
  [ ! -f /etc/chrony.conf_bak ] && cp /etc/chrony.conf{,_bak} #备份默认配置
  cat << EOF > /etc/chrony.conf
server ntp.aliyun.com iburst
server cn.ntp.org.cn iburst
server ntp.shu.edu.cn iburst
server 0.cn.pool.ntp.org iburst
server 1.cn.pool.ntp.org iburst
server 2.cn.pool.ntp.org iburst
server 3.cn.pool.ntp.org iburst

driftfile /var/lib/chrony/drift
makestep 1.0 3
logdir /var/log/chrony
EOF

  timedatectl set-timezone Asia/Shanghai
  chronyd -q -t 1 'server cn.pool.ntp.org iburst maxsamples 1'
  systemctl enable chrony
  systemctl start chrony
  chronyc sources -v
  chronyc sourcestats
  hwclock --systohc

  # package
  [[ "${OFFLINE_TAG:-}" != "1" ]] && apt-get install -y apt-transport-https ca-certificates curl wget gnupg lsb-release

  # ipvs
  [[ "${OFFLINE_TAG:-}" != "1" ]] && apt-get install -y ipvsadm ipset sysstat conntrack libseccomp2
  module=(
  ip_vs
  ip_vs_rr
  ip_vs_wrr
  ip_vs_sh
  overlay
  nf_conntrack
  br_netfilter
  )
  [ -f /etc/modules-load.d/ipvs.conf ] && cp -f /etc/modules-load.d/ipvs.conf{,_bak}
  for kernel_module in "${module[@]}";do
     /sbin/modinfo -F filename "$kernel_module" |& grep -qv ERROR && echo "$kernel_module" >> /etc/modules-load.d/ipvs.conf
  done
  systemctl restart systemd-modules-load
  systemctl enable systemd-modules-load
  sysctl --system

  # audit
  [[ "${OFFLINE_TAG:-}" != "1" ]] && apt-get install -y auditd audispd-plugins
cat << EOF >> /etc/audit/rules.d/audit.rules
## Kainstall managed start
# Ignore errors
-i

# SYSCALL
-a always,exit -F arch=b64 -S kill,tkill,tgkill -F a1=9 -F key=trace_kill_9
-a always,exit -F arch=b64 -S kill,tkill,tgkill -F a1=15 -F key=trace_kill_15

# docker
-w /usr/bin/dockerd -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /etc/systemd/system/docker.service -k docker
-w /usr/lib/systemd/system/docker.socket -k docker
-w /etc/default/docker -k docker
-w /etc/sysconfig/docker -k docker
-w /etc/docker/daemon.json -k docker

# containerd
-w /usr/bin/containerd -k containerd
-w /var/lib/containerd -k containerd
-w /usr/lib/systemd/system/containerd.service -k containerd
-w /etc/containerd/config.toml -k containerd

# cri-o
-w /usr/bin/crio -k cri-o
-w /etc/crio -k cri-o

# runc 
-w /usr/bin/runc -k runc

# kube
-w /usr/bin/kubeadm -k kubeadm
-w /usr/bin/kubelet -k kubelet
-w /usr/bin/kubectl -k kubectl
-w /var/lib/kubelet -k kubelet
-w /etc/kubernetes -k kubernetes
## Kainstall managed end
EOF
  chmod 600 /etc/audit/rules.d/audit.rules
  sed -i 's#max_log_file =.*#max_log_file = 80#g' /etc/audit/auditd.conf 
  if [ -f /usr/libexec/initscripts/legacy-actions/auditd/restart ]; then
     /usr/libexec/initscripts/legacy-actions/auditd/restart
  else
     systemctl stop auditd && systemctl start auditd
  fi
  systemctl enable auditd

  grep single-request-reopen /etc/resolv.conf || sed -i '1ioptions timeout:2 attempts:3 rotate single-request-reopen' /etc/resolv.conf

  ipvsadm --clear
  iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
}


function script::upgrade_kernel() {
  # 升级内核

  local codename; codename="$(dpkg --status tzdata|grep Provides|cut -f2 -d'-')"

  if [[ "${OFFLINE_TAG:-}" != "1" ]]; then
    echo "deb [trusted=yes] http://mirrors.aliyun.com/debian ${codename}-backports main" > /etc/apt/sources.list.d/backports.list
    apt update
    apt -t "${codename}-backports" install linux-image-amd64 linux-headers-amd64 -y
  fi 
}


function script::upgrage_kube() {
  # 节点软件升级

  local role=${1:-init}
  local version="=${2:-latest}-00"
  version="${version#=latest-00}"

  set -e
  echo '[install] kubeadm'
  kubeadm version
  apt-get update
  apt-get install -y "kubeadm${version}"
  kubeadm version

  echo '[upgrade]'
  if [[ "$role" == "init" ]]; then
    local plan_info; plan_info=$(kubeadm upgrade plan)
    local v; v=$(printf "%s" "$plan_info" | grep 'kubeadm upgrade apply ' | awk '{print $4}'| tail -1 )
    printf "%s\n" "${plan_info}"
    kubeadm upgrade apply "${v}" -y
  else
    kubeadm upgrade node
  fi

  echo '[install] kubelet kubectl'
  kubectl version --client=true
  apt-get install -y "kubelet${version}" "kubectl${version}"
  kubectl version --client=true

  [ -f /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf ] && \
    sed -i 's#^\[Service\]#[Service]\nCPUAccounting=true\nMemoryAccounting=true#g' /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf

  systemctl daemon-reload
  systemctl restart kubelet
}


function script::install_docker() {
  # 安装 docker
  
  local version="=${1:-latest}-00"
  version="${version#=latest-00}"

  wget -qO - http://mirrors.aliyun.com/docker-ce/linux/debian/gpg | sudo apt-key add -
  echo "deb [trusted=yes] http://mirrors.aliyun.com/docker-ce/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker-ce.list
  apt-get update

  if [[ "${OFFLINE_TAG:-}" != "1" ]];then
    [ -f "$(which docker)" ]  && apt remove -y docker-ce docker-ce-cli containerd.io
    apt-get install -y "docker-ce${version}" "docker-ce-cli${version}" containerd.io bash-completion
  fi

  apt-mark hold docker-ce docker-ce-cli containerd.io

  [ -f /usr/share/bash-completion/completions/docker ] && \
    cp -f /usr/share/bash-completion/completions/docker /etc/bash_completion.d/

  [ ! -d /etc/docker ] && mkdir /etc/docker
  cat << EOF > /etc/docker/daemon.json
{
  "data-root": "/var/lib/docker",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "200m",
    "max-file": "5"
  },
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 655360,
      "Soft": 655360
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 655360,
      "Soft": 655360
    }
  },
  "live-restore": true,
  "oom-score-adjust": -1000,
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10,
  "storage-driver": "overlay2",
  "storage-opts": ["overlay2.override_kernel_check=true"],
  "exec-opts": ["native.cgroupdriver=systemd"],
  "registry-mirrors": [
    "https://yssx4sxy.mirror.aliyuncs.com/"
  ]
}
EOF
  sed -i 's|#oom_score = 0|oom_score = -999|' /etc/containerd/config.toml
  cat << EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/dockershim.sock
image-endpoint: unix:///var/run/dockershim.sock
timeout: 2
debug: false
pull-image-on-create: true
disable-pull-on-run: false
EOF
  
  systemctl enable containerd
  systemctl restart containerd

  systemctl enable docker
  systemctl restart docker
}


function script::install_containerd() {
  # 安装 containerd
  
  local version="=${1:-latest}-00"
  version="${version#=latest-00}"

  wget -qO - http://mirrors.aliyun.com/docker-ce/linux/debian/gpg | sudo apt-key add -
  echo "deb [trusted=yes] http://mirrors.aliyun.com/docker-ce/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker-ce.list
  apt-get update

  if [[ "${OFFLINE_TAG:-}" != "1" ]];then
    [ -f "$(which runc)" ]  && apt remove -y runc
    [ -f "$(which containerd)" ]  && apt remove -y containerd.io
    apt-get install -y containerd.io"${version}" containernetworking bash-completion
  fi

  [ -d /etc/bash_completion.d ] && crictl completion bash > /etc/bash_completion.d/crictl

  containerd config default > /etc/containerd/config.toml
  sed -i -e "s#k8s.gcr.io#registry.cn-hangzhou.aliyuncs.com/kainstall#g" \
         -e "/containerd.runtimes.runc.options/a\ \ \ \ \ \ \ \ \ \ \ \ SystemdCgroup = true" \
         -e "s#https://registry-1.docker.io#https://yssx4sxy.mirror.aliyuncs.com#g" \
         -e "s#oom_score = 0#oom_score = -999#" \
         -e "s#max_concurrent_downloads = 3#max_concurrent_downloads = 10#g" /etc/containerd/config.toml

  cat << EOF > /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 2
debug: false
pull-image-on-create: true
disable-pull-on-run: false
EOF
  
  systemctl restart containerd
  systemctl enable containerd
}

function script::install_cri-o() {
  # 安装 cri-o
  
  local version="${1:-latest}"
  version="${version##latest}"
  os="Debian_Unstable"

  echo "deb [trusted=yes] http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$os/ /" > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
  echo "deb [trusted=yes] http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$version/$os/ /" > "/etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$version.list"

  wget -qO - "https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$version/$os/Release.key" | apt-key add -
  wget -qO - "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$os/Release.key" | apt-key add -

  apt-get update

  if [[ "${OFFLINE_TAG:-}" != "1" ]];then
    [ -f "$(which runc)" ]  && apt remove -y runc
    [ -f "$(which crio)" ]  && apt remove -y cri-o
    [ -f "$(which docker)" ]  && apt remove -y docker-ce docker-ce-cli containerd.io
    apt-get install -y cri-o runc bash-completion
  fi

  [ -d /etc/bash_completion.d ] && \
    { crictl completion bash >  /etc/bash_completion.d/crictl; \
      crio completion bash > /etc/bash_completion.d/crio; \
      crio-status completion bash > /etc/bash_completion.d/crio-status; }

  [ ! -f /etc/crio/crio.conf ] && crio config --default > /etc/crio/crio.conf
  sed -i -e "s#k8s.gcr.io#registry.cn-hangzhou.aliyuncs.com/kainstall#g" \
         -e 's|#registries = \[|registries = ["docker.io", "quay.io"]|g' /etc/crio/crio.conf

  [ -d /etc/containers/registries.conf.d ] && cat << EOF > /etc/containers/registries.conf.d/000-dockerio.conf
[[registry]]
prefix = "docker.io"
insecure = false
blocked = false
location = "docker.io"

[[registry.mirror]]
location = "yssx4sxy.mirror.aliyuncs.com"
insecure = true
EOF

  cat << EOF > /etc/crictl.yaml
runtime-endpoint: unix:///var/run/crio/crio.sock
image-endpoint: unix:///var/run/crio/crio.sock
timeout: 2
debug: false
pull-image-on-create: true
disable-pull-on-run: false
EOF

  sed -i "s#10.85.0.0/16#${KUBE_POD_SUBNET:-10.85.0.0/16}#g" /etc/cni/net.d/100-crio-bridge.conf
  cat << EOF > /etc/cni/net.d/10-crio.conf
{
$(grep cniVersion /etc/cni/net.d/100-crio-bridge.conf)
    "name": "crio",
    "type": "flannel"
}
EOF
  mv /etc/cni/net.d/100-crio-bridge.conf /etc/cni/net.d/10-crio.conf /etc/cni/net.d/200-loopback.conf /tmp/
  [ ! -d /usr/lib/cri-o-runc/sbin/ ] && mkdir -p /usr/lib/cri-o-runc/sbin/
  [ ! -f /usr/sbin/runc ] && ln -sv "$(which runc)" /usr/sbin/runc
  [ ! -f /usr/lib/cri-o-runc/sbin/runc ] && ln -sv "$(which runc)" /usr/lib/cri-o-runc/sbin/runc
  systemctl restart crio
  systemctl enable crio
}


function script::install_kube() {
  # 安装kube组件
  
  local version="=${1:-latest}-00"
  version="${version#=latest-00}"
  
  echo 'deb [trusted=yes] http://mirrors.aliyun.com/kubernetes/apt kubernetes-xenial main' > /etc/apt/sources.list.d/kubernetes.list
  wget -qO - http://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg | sudo apt-key add -
  apt-get update

  if [[ "${OFFLINE_TAG:-}" != "1" ]];then
    [ -f "$(which kubeadm)" ]  && apt remove -y kubeadm
    [ -f "$(which kubelet)" ]  && apt remove -y kubelet
    [ -f "$(which kubectl)" ]  && apt remove -y kubectl
    apt-get install -y "kubeadm${version}" "kubelet${version}" "kubectl${version}" kubernetes-cni
  fi

  [ -d /etc/bash_completion.d ] && \
    { kubectl completion bash > /etc/bash_completion.d/kubectl; \
      kubeadm completion bash > /etc/bash_completion.d/kubadm; }

  [ ! -d /usr/lib/systemd/system/kubelet.service.d ] && mkdir -p /usr/lib/systemd/system/kubelet.service.d
  cat << EOF > /usr/lib/systemd/system/kubelet.service.d/11-cgroup.conf
[Service]
CPUAccounting=true
MemoryAccounting=true
BlockIOAccounting=true
ExecStartPre=/bin/bash -c '/bin/mkdir -p /sys/fs/cgroup/{cpuset,memory,hugetlb,systemd,pids,"cpu,cpuacct"}/{system,kube,kubepods}.slice||:'
Slice=kube.slice
EOF
  systemctl daemon-reload

  systemctl enable kubelet
  systemctl restart kubelet
}


function script::install_haproxy() {
  # 安装haproxy
   
  local api_servers="$*"
   
  if [[ "${OFFLINE_TAG:-}" != "1" ]];then
    [ -f "$(which haproxy)" ] && apt remove -y haproxy
    apt-get install -y haproxy
  fi

  [ ! -f /etc/haproxy/haproxy.cfg_bak ] && cp /etc/haproxy/haproxy.cfg{,_bak}
cat << EOF > /etc/haproxy/haproxy.cfg
global
  log /dev/log    local0
  log /dev/log    local1 notice
  tune.ssl.default-dh-param 2048

defaults
  log global
  mode http
  option dontlognull
  timeout connect 5000ms
  timeout client 600000ms
  timeout server 600000ms

listen stats
    bind :19090
    mode http
    balance
    stats uri /haproxy_stats
    stats auth admin:admin123
    stats admin if TRUE

frontend kube-apiserver-https
   mode tcp
   option tcplog
   bind :6443
   default_backend kube-apiserver-backend

backend kube-apiserver-backend
    mode tcp
    balance roundrobin
    stick-table type ip size 200k expire 30m
    stick on src
$(index=1;for h in $api_servers;do echo "    server apiserver${index} $h:6443 check";index=$((index+1));done)
EOF

  systemctl enable haproxy
  systemctl restart haproxy
}


function check::command_exists() {
  # 检查命令是否存在
  
  local cmd=${1}
  local package=${2}

  if command -V "$cmd" > /dev/null 2>&1; then
    log::info "[check]" "$cmd command exists."
  else
    log::warning "[check]" "I require $cmd but it's not installed."
    log::warning "[check]" "install $package package."
    command::exec "127.0.0.1" "apt-get install -y ${package}"
    check::exit_code "$?" "check" "$package install" "exit"
  fi
}


function check::command() {
  # 检查用到的命令
  
  check::command_exists ssh openssh-clients
  check::command_exists sshpass sshpass
  check::command_exists wget wget
  [[ "${OFFLINE_TAG:-}" == "1" ]] && check::command_exists tar tar
}


function check::ssh_conn() {
  # 检查ssh连通性

  for host in $MASTER_NODES $WORKER_NODES
  do
    [ "$host" == "127.0.0.1" ] && continue
    command::exec "${host}" "echo 0"
    check::exit_code "$?" "check" "ssh $host connection" "exit"
  done
}


function check::os() {
  # 检查os系统支持

  log::info "[check]" "os support: ${OS_SUPPORT}"
  for host in $MASTER_NODES $WORKER_NODES
  do
    command::exec "${host}" "
      [ -f /etc/os-release ] && source /etc/os-release
      echo client_os:\${ID:-}\${VERSION_ID:-}
      if [[ \"${OS_SUPPORT}\" == *\"\${ID:-}\${VERSION_ID:-}\"* ]]; then
        exit 0
      fi
      exit 1
    "
    check::exit_code "$?" "check" "$host os support" "exit"
  done
}


function check::kernel() {
  # 检查os kernel 版本

  local version=${1:-}
  log::info "[check]" "kernel version not less than ${version}"
  version=$(echo "${version}" | awk -F. '{ printf("%d%03d%03d\n", $1,$2,$3); }')

  for host in $MASTER_NODES $WORKER_NODES
  do
    command::exec "${host}" "
      kernel_version=\$(uname -r)
      kernel_version=\$(echo \${kernel_version/-*} | awk -F. '{ printf(\"%d%03d%03d\n\", \$1,\$2,\$3); }') 
      echo kernel_version \${kernel_version}
      [[ \${kernel_version} -ge ${version} ]] && exit 0 || exit 1
    "                                                                                                                                                 
    check::exit_code "$?" "check" "$host kernel version" "exit"
  done

}

function check::apiserver_conn() {
  # 检查apiserver连通性

  command::exec "${MGMT_NODE}" "kubectl get node"
  check::exit_code "$?" "check" "conn apiserver" "exit"
}


function check::exit_code() {
  # 检查返回码

  local code=${1:-}
  local app=${2:-}
  local desc=${3:-}
  local exit_script=${4:-}

  if [[ "${code}" == "0" ]]; then
    log::info "[${app}]" "${desc} succeeded."
  else
    log::error "[${app}]" "${desc} failed."
    [[ "$exit_script" == "exit" ]] && exit "$code"
  fi
}


function check::preflight() {
  # 预检
  
  # check command
  check::command

  # check ssh conn
  check::ssh_conn

  # check os
  check::os

  # check os kernel
  [[ "${KUBE_NETWORK:-}" == "cilium" ]] && check::kernel 4.9.17

  # check apiserver conn
  if [[ $(( ${ADD_TAG:-0} + ${DEL_TAG:-0} + ${UPGRADE_TAG:-0} + ${RENEW_CERT_TAG:-0} )) -gt 0 ]]; then
    check::apiserver_conn
  fi
}


function install::package() {
  # 安装包
 
  if [[ "${KUBE_CRI}" == "cri-o" && "${KUBE_CRI_VERSION}" == "latest" ]]; then
    KUBE_CRI_VERSION="${KUBE_VERSION}"
    if [[ "${KUBE_CRI_VERSION}" == "latest" ]]; then
      if command::exec "127.0.0.1" "wget https://storage.googleapis.com/kubernetes-release/release/stable.txt -q -O -"; then
        KUBE_CRI_VERSION="${COMMAND_OUTPUT#v}"
      else
        log::error "[install]" "get kubernetes stable version error. Please specify the version!"
        exit 1
      fi
    fi
    KUBE_CRI_VERSION="${KUBE_CRI_VERSION%.*}"
  fi

  for host in $MASTER_NODES $WORKER_NODES
  do
    # install cri
    log::info "[install]" "install ${KUBE_CRI} on $host."
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      $(declare -f script::install_"${KUBE_CRI}")
      script::install_${KUBE_CRI} $KUBE_CRI_VERSION
    "
    check::exit_code "$?" "install" "install ${KUBE_CRI} on $host"

    # install kube
    log::info "[install]" "install kube on $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      $(declare -f script::install_kube)
      script::install_kube $KUBE_VERSION
    "
    check::exit_code "$?" "install" "install kube on $host"
  done

  local apiservers=$MASTER_NODES
  if [[ "$apiservers" == "127.0.0.1" ]]; then
    command::exec "${MGMT_NODE}" "ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'"
    get::command_output "apiservers" "$?"
  fi

  if [[ "${ADD_TAG:-}" == "1" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
    "
    get::command_output "apiservers" "$?"
  fi
  
  for host in $WORKER_NODES
  do
    # install haproxy
    log::info "[install]" "install haproxy on $host"
  command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      $(declare -f script::install_haproxy)
      script::install_haproxy \"$apiservers\"
  "
    check::exit_code "$?" "install" "install haproxy on $host"
  done
  
  # 10年证书
  if [[ "${CERT_YEAR_TAG:-}" == "1" ]]; then
    local version="${KUBE_VERSION}"
    
    if [[ "${version}" == "latest" ]]; then
      if command::exec "127.0.0.1" "wget https://storage.googleapis.com/kubernetes-release/release/stable.txt -q -O -"; then
        version="${COMMAND_OUTPUT#v}"
      else
        log::error "[install]" "get kubernetes stable version error. Please specify the version!"
        exit 1
      fi
    fi
    
    log::info "[install]" "download kubeadm 10 years certs client"
    local certs_file="${OFFLINE_DIR}/bins/kubeadm-linux-amd64"
    MGMT_NODE="127.0.0.1" utils::download_file "${GITHUB_PROXY}https://github.com/lework/kubeadm-certs/releases/download/v${version}/kubeadm-linux-amd64" "${certs_file}"
    
    for host in $MASTER_NODES $WORKER_NODES
    do
      log::info "[install]" "scp kubeadm client to $host"
      command::scp "${host}" "${certs_file}" "/tmp/kubeadm-linux-amd64"
      check::exit_code "$?" "install" "scp kubeadm client to $host" "exit"

      command::exec "${host}" "
        set -e
        if [[ -f /tmp/kubeadm-linux-amd64 ]]; then
        [[ -f /usr/bin/kubeadm && ! -f /usr/bin/kubeadm_src ]] && mv -fv /usr/bin/kubeadm{,_src}
          mv -fv /tmp/kubeadm-linux-amd64 /usr/bin/kubeadm
          chmod +x /usr/bin/kubeadm
        else
          echo \"not found /tmp/kubeadm-linux-amd64\"
          exit 1
        fi
    "
      check::exit_code "$?" "install" "$host: use kubeadm 10 years certs client"
    done
  fi
}


function init::upgrade_kernel() {
  # 升级节点内核

  [[ "${UPGRADE_KERNEL_TAG:-}" != "1" ]] && return

  for host in $MASTER_NODES $WORKER_NODES
  do
    log::info "[init]" "upgrade kernel: $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      $(declare -f script::upgrade_kernel)
      script::upgrade_kernel
    "
    check::exit_code "$?" "init" "upgrade kernel $host" "exit"
  done
  
  for host in $MASTER_NODES $WORKER_NODES
  do
    command::exec "${host}" "bash -c 'sleep 15 && reboot' &>/dev/null &"
    check::exit_code "$?" "init" "$host: Wait for 15s to restart"
  done

  log::info "[notice]" "Please execute the command again!" 
  log::access "[command]" "bash $0 ${SCRIPT_PARAMETER// --upgrade-kernel/}"
  exit 0
}


function cert::renew_node() {
 # 节点证书续期
 
  local role="${1:-master}"
  local hosts=""
  local kubelet_config=""
  
  command::exec "${MGMT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/${role}' -o jsonpath='{range.items[*]}{.metadata.name } {end}'
  "
  get::command_output "hosts" "$?"
  
  for host in ${hosts}
  do
    log::info "[cert]" "drain $host"
    command::exec "${MGMT_NODE}" "kubectl drain $host --force --ignore-daemonsets --delete-local-data"
    check::exit_code "$?" "cert" "$host: drain"
    sleep 5
    
    if [[ "${role}" == "master" ]]; then 
      command::exec "${host}" "cp -rf /etc/kubernetes /etc/kubernetes_\$(date +%Y-%m-%d)"
      check::exit_code "$?" "cert" "$host: backup kubernetes config"
      
      command::exec "${host}" "kubeadm certs renew all 2>/dev/null|| kubeadm alpha certs renew all"
      check::exit_code "$?" "cert" "$host: renew certs"
      
      command::exec "${host}" "
        $(declare -f utils::retry)
        kill -s SIGHUP \$(pidof etcd) && \
        utils::retry 10 \"echo -n | openssl s_client -connect localhost:2379 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout | grep Not\"
      "
      check::exit_code "$?" "cert" "$host: restart etcd"
      
      command::exec "${host}" "
        $(declare -f utils::retry)
        kill -s SIGHUP \$(pidof kube-apiserver) && \
        utils::retry 10 \"echo -n | openssl s_client -connect localhost:6443 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout | grep Not\"
      "
      check::exit_code "$?" "cert" "$host: restart kube-apiserver"
      
      command::exec "${host}" "
        $(declare -f utils::retry)
        kill -s SIGHUP \$(pidof kube-controller-manager) && \
        utils::retry 10 \"echo -n | openssl s_client -connect localhost:10257 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout | grep Not\"
       "
      check::exit_code "$?" "cert" "$host: restart kube-controller-manager"
      
      command::exec "${host}" "
        $(declare -f utils::retry)
        kill -s SIGHUP \$(pidof kube-scheduler) && \
        utils::retry 10 \"echo -n | openssl s_client -connect localhost:10259 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout | grep Not\"
      "
      check::exit_code "$?" "cert" "$host: restart kube-scheduler"
    fi

    log::info "[cert]" "get kubelet config"
    command::exec "${MGMT_NODE}" "
      kubeadm kubeconfig user --org system:nodes --client-name system:node:${host}  --config /etc/kubernetes/kubeadmcfg.yaml || kubeadm alpha kubeconfig user --org system:nodes --client-name system:node:${host}  --config /etc/kubernetes/kubeadmcfg.yaml
    "
    get::command_output "kubelet_config" "$?" "exit"

    if [[ "$kubelet_config" != "" ]]; then
      log::info "[cert]" "copy kubelet config"
      command::exec "${host}" "
        cp /etc/kubernetes/kubelet.conf /etc/kubernetes/kubelet.conf_bak
        echo '$(printf "%s" "${kubelet_config}" | sed 's#https://.*:#https://127.0.0.1:#g')' > /etc/kubernetes/kubelet.conf
      "
      check::exit_code "$?" "cert" "$host: copy kubelet config"

      command::exec "${host}" "rm -rfv /var/lib/kubelet/pki/*"
      check::exit_code "$?" "cert" "$host: delete kubelet pki files"

      command::exec "${host}" "
        $(declare -f utils::retry)
        systemctl restart kubelet && \
        utils::retry 10 \"echo -n | openssl s_client -connect localhost:10250 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout | grep Not\"
      "
      local status="$?"
      check::exit_code "${status}" "cert" "$host: restart kubelet"
      if [[ "${status}" == "0" ]]; then
        sleep 5
        command::exec "${MGMT_NODE}" "kubectl uncordon ${host}"
        check::exit_code "$?" "cert" "uncordon ${host} node"
      fi
    fi
  done
}


function cert::renew() {
  # 证书续期
 
  log::info "[cert]" "renew cluster cert"
  cert::renew_node "master"
  cert::renew_node "worker"
 
  log::info "[cert]" "cluster status"
  command::exec "${MGMT_NODE}" "
    echo
    kubectl get node
    echo
    kubeadm certs check-expiration 2>/dev/null || kubeadm alpha certs check-expiration
  " && printf "%s" "${COMMAND_OUTPUT}"
}


function init::node_config() {
  # 初始化节点配置

  local master_index=${master_index:-1}
  local worker_index=${worker_index:-1}
  
  log::info "[init]" "Get $MGMT_NODE InternalIP."
  command::exec "${MGMT_NODE}" "
    ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print \$7}'
  "
  get::command_output "MGMT_NODE_IP" "$?" "exit"

  # master
  for host in $MASTER_NODES
  do
    log::info "[init]" "master: $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0} KUBE_APISERVER=${KUBE_APISERVER} SKIP_SET_OS_REPO=${SKIP_SET_OS_REPO:-false}
      $(declare -f script::init_node)
      script::init_node
   "
    check::exit_code "$?" "init" "init master $host"

    # 设置主机名和解析
    command::exec "${host}" "
      printf \"\\n${MGMT_NODE_IP} $KUBE_APISERVER\\n$node_hosts\" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-master-node${master_index}
    "
    check::exit_code "$?" "init" "$host set hostname and hostname resolution"

    # set audit-policy
    log::info "[init]" "$host: set audit-policy file."
    command::exec "${host}" "
      [ ! -d etc/kubernetes ] && mkdir -p /etc/kubernetes
      cat << EOF > /etc/kubernetes/audit-policy.yaml
# Log all requests at the Metadata level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
EOF
    "
    check::exit_code "$?" "init" "$host: set audit-policy file" "exit"
    master_index=$((master_index + 1))
  done
   
  # worker
  for host in $WORKER_NODES
  do
    log::info "[init]" "worker: $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0} KUBE_APISERVER=${KUBE_APISERVER} SKIP_SET_OS_REPO=${SKIP_SET_OS_REPO:-false}
      $(declare -f script::init_node)
      script::init_node
    "
    check::exit_code "$?" "init" "init worker $host"

    # 设置主机名和解析
    command::exec "${host}" "
      printf \"\\n127.0.0.1 $KUBE_APISERVER\\n$node_hosts\" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-worker-node${worker_index}
    "
    worker_index=$((worker_index + 1))
  done
}


function init::node() {
  # 初始化节点
  
  init::upgrade_kernel

  local node_hosts=""
  local i=1
  for h in $MASTER_NODES
  do
    node_hosts="${node_hosts}\n$h ${HOSTNAME_PREFIX}-master-node${i}"
    i=$((i + 1))
  done
  
  local i=1
  for h in $WORKER_NODES
  do
    node_hosts="${node_hosts}\n$h ${HOSTNAME_PREFIX}-worker-node${i}"
    i=$((i + 1))
  done

  init::node_config
}


function init::add_node() {
  # 初始化添加的节点
  
  init::upgrade_kernel

  local master_index=0
  local worker_index=0
  local node_hosts=""
  local add_node_hosts=""

  command::exec "${MGMT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address } {end}' | awk '{print \$1}'
  "
  get::command_output "MGMT_NODE" "$?" "exit"

  # 获取现有集群节点主机名
  command::exec "${MGMT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {.metadata.name }\\n{end}'
  "
  get::command_output "node_hosts" "$?" "exit"
  
  for host in $MASTER_NODES $WORKER_NODES
  do
    if [[ $node_hosts == *"$host"* ]]; then
      log::error "[init]" "The host $host is already in the cluster!"
      exit 1
    fi
  done
  
  if [[ "$MASTER_NODES" != "" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].metadata.name}' | grep -Eo '[0-9]+\$'
    "
    get::command_output "master_index" "$?" "exit"
    master_index=$(( master_index + 1 ))
    local i=$master_index
    for host in $MASTER_NODES
    do
      add_node_hosts="${add_node_hosts}\n${host:-} ${HOSTNAME_PREFIX}-master-node${i}"
      i=$((i + 1))
    done
  fi

  if [[ "$WORKER_NODES" != "" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='!node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].metadata.name}' | grep -Eo '[0-9]+\$' || echo 0
    "
    get::command_output "worker_index" "$?" "exit"
    worker_index=$(( worker_index + 1 ))
    local i=$worker_index
    for host in $WORKER_NODES
    do
      add_node_hosts="${add_node_hosts}\n${host:-} ${HOSTNAME_PREFIX}-worker-node${i}"
      i=$((i + 1))
    done
  fi
  #向集群节点添加新增的节点主机名解析 
  for host in $(echo -ne "$node_hosts" | awk '{print $1}')
  do
     command::exec "${host}" "
       printf \"$add_node_hosts\" >> /etc/hosts
     "
     check::exit_code "$?" "init" "$host add new node hostname resolution"
  done

  node_hosts="${node_hosts}\n${add_node_hosts}"
  init::node_config
}


function kubeadm::init() {
  # 集群初始化
  
  log::info "[kubeadm init]" "kubeadm init on ${MGMT_NODE}"
  log::info "[kubeadm init]" "${MGMT_NODE}: set kubeadmcfg.yaml"
  command::exec "${MGMT_NODE}" "
    PAUSE_VERSION=$(kubeadm config images list 2>/dev/null | awk -F: '/pause/ {print $2}')
    cat << EOF > /etc/kubernetes/kubeadmcfg.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
${kubelet_nodeRegistration}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
ipvs:
  minSyncPeriod: 5s
  syncPeriod: 5s
  # ipvs 负载策略
  scheduler: 'wrr'

---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
maxPods: 200
cgroupDriver: systemd
runtimeRequestTimeout: 5m
# 此配置保证了 kubelet 能在 swap 开启的情况下启动
failSwapOn: false
nodeStatusUpdateFrequency: 5s
rotateCertificates: true
imageGCLowThresholdPercent: 70
imageGCHighThresholdPercent: 80
# 软驱逐阀值
evictionSoft:
  imagefs.available: 15%
  memory.available: 512Mi
  nodefs.available: 15%
  nodefs.inodesFree: 10%
# 达到软阈值之后，持续时间超过多久才进行驱逐
evictionSoftGracePeriod:
  imagefs.available: 3m
  memory.available: 1m
  nodefs.available: 3m
  nodefs.inodesFree: 1m
# 硬驱逐阀值
evictionHard:
  imagefs.available: 10%
  memory.available: 256Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
evictionMaxPodGracePeriod: 30
# 节点资源预留
kubeReserved:
  cpu: 200m\$(if [[ \$(cat /proc/meminfo | awk '/MemTotal/ {print \$2}') -gt 3670016 ]]; then echo -e '\n  memory: 256Mi';fi)
  ephemeral-storage: 1Gi
systemReserved:
  cpu: 300m\$(if [[ \$(cat /proc/meminfo | awk '/MemTotal/ {print \$2}') -gt 3670016 ]]; then echo -e '\n  memory: 512Mi';fi)
  ephemeral-storage: 1Gi
kubeReservedCgroup: /kube.slice
systemReservedCgroup: /system.slice
enforceNodeAllocatable: 
- pods

---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: $KUBE_VERSION
controlPlaneEndpoint: $KUBE_APISERVER:6443
networking:
  dnsDomain: $KUBE_DNSDOMAIN
  podSubnet: $KUBE_POD_SUBNET
  serviceSubnet: $KUBE_SERVICE_SUBNET
imageRepository: $KUBE_IMAGE_REPO
apiServer:
  certSANs:
  - 127.0.0.1
  - $KUBE_APISERVER
$(for h in $MASTER_NODES;do echo "  - $h";done)
  extraArgs:
    event-ttl: '720h'
    service-node-port-range: '30000-50000'
    # 审计日志相关配置
    audit-log-maxage: '20'
    audit-log-maxbackup: '10'
    audit-log-maxsize: '100'
    audit-log-path: /var/log/kube-audit/audit.log
    audit-policy-file: /etc/kubernetes/audit-policy.yaml
  extraVolumes:
  - name: audit-config
    hostPath: /etc/kubernetes/audit-policy.yaml
    mountPath: /etc/kubernetes/audit-policy.yaml
    readOnly: true
    pathType: File
  - name: audit-log
    hostPath: /var/log/kube-audit
    mountPath: /var/log/kube-audit
    pathType: DirectoryOrCreate
  - name: localtime
    hostPath: /etc/localtime
    mountPath: /etc/localtime
    readOnly: true
    pathType: File
controllerManager:
  extraArgs:
    bind-address: 0.0.0.0
    node-cidr-mask-size: '24'
    deployment-controller-sync-period: '10s'
    node-monitor-grace-period: '20s'
    pod-eviction-timeout: '2m'
    terminated-pod-gc-threshold: '30'
    experimental-cluster-signing-duration: 87600h
    feature-gates: RotateKubeletServerCertificate=true
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
    pathType: File
scheduler:
  extraArgs:
    bind-address: 0.0.0.0
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
    pathType: File
$(if [[ "${KUBE_VERSION}" == "1.21.1" ]]; then
echo "dns:
  type: CoreDNS
  imageRepository: docker.io
  imageTag: 1.8.0"
fi)
EOF
"
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: set kubeadmcfg.yaml" "exit"
  
  log::info "[kubeadm init]" "${MGMT_NODE}: kubeadm init start."
  command::exec "${MGMT_NODE}" "kubeadm init --config=/etc/kubernetes/kubeadmcfg.yaml --upload-certs"
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: kubeadm init" "exit"
  
  sleep 3
  
  log::info "[kubeadm init]" "${MGMT_NODE}: set kube config."
  command::exec "${MGMT_NODE}" "
     mkdir -p \$HOME/.kube
     sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config
  "
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: set kube config" "exit"
  if [[ "$(echo "$MASTER_NODES" | wc -w)" == "1" ]]; then
    log::info "[kubeadm init]" "${MGMT_NODE}: delete master taint"
    command::exec "${MGMT_NODE}" "kubectl taint nodes --all node-role.kubernetes.io/master-"
    check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: delete master taint"
  fi

  command::exec "${MGMT_NODE}" "
    kubectl create clusterrolebinding node-client-auto-approve-csr --clusterrole=system:certificates.k8s.io:certificatesigningrequests:nodeclient --user=kubelet-bootstrap
    kubectl create clusterrolebinding node-client-auto-renew-crt --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeclient --group=system:nodes
    kubectl create clusterrolebinding node-server-auto-renew-crt --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeserver --group=system:nodes
  "
  check::exit_code "$?" "kubeadm init" "Auto-Approve kubelet cert csr" "exit"
}


function kubeadm::join() {
  # 加入集群

  log::info "[kubeadm join]" "master: get join token and cert info"
  command::exec "${MGMT_NODE}" "
    openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //'
  "
  get::command_output "CACRT_HASH" "$?" "exit"
  
  command::exec "${MGMT_NODE}" "
    kubeadm init phase upload-certs --upload-certs --config /etc/kubernetes/kubeadmcfg.yaml 2>> /dev/null | tail -1
  "
  get::command_output "INTI_CERTKEY" "$?" "exit"
  
  command::exec "${MGMT_NODE}" "
    kubeadm token create
  "
  get::command_output "INIT_TOKEN" "$?" "exit"

  command::exec "${MGMT_NODE}" "
    kubeadm config images list 2>/dev/null | awk -F: '/pause/ {print \$2}'
  "
  get::command_output "PAUSE_VERSION" "$?"

  for host in $MASTER_NODES
  do
    [[ "${MGMT_NODE}" == "$host" ]] && continue
    log::info "[kubeadm join]" "master $host join cluster."
    command::exec "${host}" "
      cat << EOF > /etc/kubernetes/kubeadmcfg.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: $KUBE_APISERVER:6443
    caCertHashes:
    - sha256:${CACRT_HASH:-}
    token: ${INIT_TOKEN}
  timeout: 5m0s
controlPlane:
  certificateKey: ${INTI_CERTKEY:-}
${kubelet_nodeRegistration}
EOF
      kubeadm join --config /etc/kubernetes/kubeadmcfg.yaml
    "
    check::exit_code "$?" "kubeadm join" "master $host join cluster"

    log::info "[kubeadm join]" "$host: set kube config."
    command::exec "${host}" "
      mkdir -p \$HOME/.kube
      sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config
    "
    check::exit_code "$?" "kubeadm join" "$host: set kube config" "exit"
    
    command::exec "${host}" "
      sed -i 's#.*$KUBE_APISERVER#127.0.0.1 $KUBE_APISERVER#g' /etc/hosts
    "
  done

  for host in $WORKER_NODES
  do
    log::info "[kubeadm join]" "worker $host join cluster."
    command::exec "${host}" "
      mkdir -p /etc/kubernetes/manifests
      cat << EOF > /etc/kubernetes/kubeadmcfg.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: $KUBE_APISERVER:6443
    caCertHashes:
    - sha256:${CACRT_HASH:-}
    token: ${INIT_TOKEN}
  timeout: 5m0s
${kubelet_nodeRegistration}
EOF
      kubeadm join --config /etc/kubernetes/kubeadmcfg.yaml
    "
    check::exit_code "$?" "kubeadm join" "worker $host join cluster"
  
    log::info "[kubeadm join]" "set $host worker node role."
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='!node-role.kubernetes.io/master' | grep '<none>' | awk '{print \"kubectl label node \" \$1 \" node-role.kubernetes.io/worker= --overwrite\" }' | bash
    "
    check::exit_code "$?" "kubeadm join" "set $host worker node role"
  done
}


function kube::wait() {
  # 等待资源完成

  local app=$1
  local namespace=$2
  local resource=$3
  local selector=${4:-}

  sleep 3
  log::info "[waiting]" "waiting $app"
  command::exec "${MGMT_NODE}" "
    $(declare -f utils::retry)
    utils::retry 6 kubectl wait --namespace ${namespace} \
    --for=condition=ready ${resource} \
    --selector=$selector \
    --timeout=60s
  "
  local status="$?"
  check::exit_code "$status" "waiting" "$app ${resource} ready"
  return "$status"
}


function kube::apply() {
  # 应用manifest

  local file=$1

  log::info "[apply]" "$file"
  command::exec "${MGMT_NODE}" "
    $(declare -f utils::retry)
    if [ -f \"$file\" ]; then
      utils::retry 6 kubectl apply --wait=true --timeout=10s -f \"$file\"
    else
      utils::retry 6 \"cat <<EOF | kubectl apply --wait=true --timeout=10s -f -
\$(printf \"%s\" \"${2:-}\")
EOF
      \"
    fi
  "
  local status="$?"
  check::exit_code "$status" "apply" "add $file"
  return "$status"
}


function kube::status() {
  # 集群状态
  
  sleep 5
  log::info "[cluster]" "cluster status"
  command::exec "${MGMT_NODE}" "
     echo
     kubectl get node -o wide
     echo
     kubectl get pods -A
  " && printf "%s" "${COMMAND_OUTPUT}"
}


function config::haproxy_backend() {
  # 添加或删除haproxy的后端server

  local action=${1:-add}
  local action_cmd=""
  local master_nodes
  
  if [[ "$MASTER_NODES" == "" || "$MASTER_NODES" == "127.0.0.1" ]]; then
    return
  fi

  command::exec "${MGMT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
  "
  get::command_output "master_nodes" "$?" "exit"
  
  for m in $MASTER_NODES
  do
    if [[ "${action}" == "add" ]]; then
      num=$(echo "${m}"| awk -F'.' '{print $4}')
      action_cmd="${action_cmd}\necho \"    server apiserver${num} ${m}:6443 check\" >> /etc/haproxy/haproxy.cfg"
    else
      [[ "${master_nodes}" == *"${m}"* ]] || return
      action_cmd="${action_cmd}\n sed -i -e \"/${m}/d\" /etc/haproxy/haproxy.cfg"
    fi
  done
        
  command::exec "${MGMT_NODE}" "
    kubectl get node --selector='!node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
  "
  get::command_output "worker_nodes" "$?"
  
  for host in ${worker_nodes:-}
  do
    log::info "[config]" "worker ${host}: ${action} apiserver from haproxy"
    command::exec "${host}" "
      $(echo -ne "${action_cmd}")
      haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy
    "
    check::exit_code "$?" "config" "worker ${host}: ${action} apiserver(${m}) from haproxy"
  done
}


function config::etcd_snapshot() {
  # 更新 etcd 备份副本

  command::exec "${MGMT_NODE}" "
    count=\$(kubectl get node --selector='node-role.kubernetes.io/master' --no-headers | wc -l)
    kubectl -n kube-system patch cronjobs etcd-snapshot --patch \"
spec:
  jobTemplate:
    spec:
      completions: \${count:-1}
      parallelism: \${count:-1}
\"
  "
  check::exit_code "$?" "config" "etcd-snapshot completions options"
}


function get::command_output() {
   # 获取命令的返回值

   local app="$1"
   local status="$2"
   local is_exit="${3:-}"
   
   if [[ "$status" == "0" && "${COMMAND_OUTPUT}" != "" ]]; then
     log::info "[command]" "get $app value succeeded."
     eval "$app=\"${COMMAND_OUTPUT}\""
   else
     log::error "[command]" "get $app value failed."
     [[ "$is_exit" == "exit" ]] && exit "$status"
   fi
   return "$status"
}


function get::ingress_conn(){
  # 获取ingress连接地址

  local port="${1:-80}"
  local ingress_name="${2:-ingress-${KUBE_INGRESS}-controller}"
  
  command::exec "${MGMT_NODE}" "
    kubectl get node -o jsonpath='{range .items[*]}{ .status.addresses[?(@.type==\"InternalIP\")].address} {.status.conditions[?(@.status == \"True\")].status}{\"\\n\"}{end}' | awk '{if(\$2==\"True\")a=\$1}END{print a}'
  "
  get::command_output "node_ip" "$?"

  command::exec "${MGMT_NODE}" "
    kubectl get svc --all-namespaces -o go-template=\"{{range .items}}{{if eq .metadata.name \\\"${ingress_name}\\\"}}{{range.spec.ports}}{{if eq .port ${port}}}{{.nodePort}}{{end}}{{end}}{{end}}{{end}}\"
  "
  
  get::command_output "node_port" "$?"
 
  INGRESS_CONN="${node_ip:-nodeIP}:${node_port:-nodePort}"
}


function add::ingress() {
  # 添加ingress组件

  local add_ingress_demo=0

  if [[ "$KUBE_INGRESS" == "nginx" ]]; then
    log::info "[ingress]" "add ingress-nginx"
    
    local ingress_nginx_file="${OFFLINE_DIR}/manifests/ingress-nginx.yml"
    utils::download_file "https://cdn.jsdelivr.net/gh/kubernetes/ingress-nginx@controller-v${INGRESS_NGINX}/deploy/static/provider/baremetal/deploy.yaml" "${ingress_nginx_file}"
    command::exec "${MGMT_NODE}" "
      sed -i -e 's#k8s.gcr.io/ingress-nginx#${KUBE_IMAGE_REPO}#g' \
             -e 's#@sha256:.*\$##g' '${ingress_nginx_file}'
    "
    check::exit_code "$?" "ingress" "change ingress-nginx manifests"
    kube::apply "${ingress_nginx_file}"

    kube::wait "ingress-nginx" "ingress-nginx" "pod" "app.kubernetes.io/component=controller" && add_ingress_demo=1

    command::exec "${MGMT_NODE}" "kubectl delete -A ValidatingWebhookConfiguration ingress-nginx-admission"
    check::exit_code "$?" "ingress" "delete ingress-ngin ValidatingWebhookConfiguration"

  elif [[ "$KUBE_INGRESS" == "traefik" ]]; then
    log::info "[ingress]" "add ingress-traefik"
    kube::apply "traefik" """
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: ingress-traefik-controller
rules:
  - apiGroups:
      - ''
    resources:
      - services
      - endpoints
      - secrets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - extensions
      - networking.k8s.io
    resources:
      - ingresses
      - ingressclasses
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - extensions
    resources:
      - ingresses/status
    verbs:
      - update
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: ingress-traefik-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ingress-traefik-controller
subjects:
  - kind: ServiceAccount
    name: ingress-traefik-controller
    namespace: default
--- 
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ingress-traefik-controller
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: ingress-traefik-controller
  labels:
    app: ingress-traefik-controller
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ingress-traefik-controller
  template:
    metadata:
      labels:
        app: ingress-traefik-controller
    spec:
      serviceAccountName: ingress-traefik-controller
      containers:
        - name: traefik
          image: traefik:v${TRAEFIK_VERSION}
          args:
            - --api.debug=true
            - --api.insecure=true
            - --log=true
            - --log.level=debug
            - --ping=true
            - --accesslog=true
            - --entrypoints.http.Address=:80
            - --entrypoints.https.Address=:443
            - --entrypoints.traefik.Address=:8080
            - --providers.kubernetesingress
            - --serverstransport.insecureskipverify=true
          ports:
            - name: http
              containerPort: 80
              protocol: TCP
            - name: https
              containerPort: 443
              protocol: TCP
            - name: admin
              containerPort: 8080
              protocol: TCP
          livenessProbe:
            failureThreshold: 2
            httpGet:
              path: /ping
              port: admin
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 5
            successThreshold: 1
            timeoutSeconds: 1
          readinessProbe:
            failureThreshold: 3
            httpGet:
              path: /ping
              port: admin
              scheme: HTTP
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
          resources:
            limits:
              cpu: 250m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 64Mi
          securityContext:
            capabilities:
              add:
              - NET_BIND_SERVICE
              drop:
              - ALL
      restartPolicy: Always
      serviceAccount: ingress-traefik-controller
      serviceAccountName: ingress-traefik-controller
---
apiVersion: v1
kind: Service
metadata:
  name: ingress-traefik-controller
spec:
  type: NodePort
  selector:
    app: ingress-traefik-controller
  ports:
    - protocol: TCP
      port: 80
      name: http
      targetPort: 80
    - protocol: TCP
      port: 443
      name: https
      targetPort: 443
    - protocol: TCP
      port: 8080
      name: admin
      targetPort: 8080
"""
    kube::wait "traefik" "default" "pod" "app=ingress-traefik-controller" && add_ingress_demo=1
  else
    log::warning "[ingress]" "No $KUBE_INGRESS config."
  fi

  if [[ "$add_ingress_demo" == "1" ]]; then
    log::info "[ingress]" "add ingress default-http-backend"
    kube::apply "default-http-backend" """
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: default-http-backend
  labels:
    app.kubernetes.io/name: default-http-backend
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: default-http-backend
  template:
    metadata:
      labels:
        app.kubernetes.io/name: default-http-backend
    spec:
      terminationGracePeriodSeconds: 60
      containers:
      - name: default-http-backend
        image: ${KUBE_IMAGE_REPO}/defaultbackend-amd64:1.5
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 30
          timeoutSeconds: 5
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: 10m
            memory: 20Mi
          requests:
            cpu: 10m
            memory: 20Mi
---
apiVersion: v1
kind: Service
metadata:
  name: default-http-backend
  namespace: kube-system
  labels:
    app.kubernetes.io/name: default-http-backend
spec:
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app.kubernetes.io/name: default-http-backend
"""
    log::info "[ingress]" "add ingress app demo"
    kube::apply "ingress-demo-app" """
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingress-demo-app
  labels:
    app: ingress-demo-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ingress-demo-app
  template:
    metadata:
      labels:
        app: ingress-demo-app
    spec:
      containers:
      - name: whoami
        image: traefik/whoami:v1.6.1
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: ingress-demo-app
spec:
  type: ClusterIP
  selector:
    app: ingress-demo-app
  ports:
    - name: http
      port: 80
      targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo-app
  annotations:
    kubernetes.io/ingress.class: ${KUBE_INGRESS}
spec:
  rules:
  - host: app.demo.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ingress-demo-app
            port:
              number: 80
"""
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then
      get::ingress_conn
      log::access "[ingress]" "curl -H 'Host:app.demo.com' http://${INGRESS_CONN}"
    fi
  fi
}


function add::network() {
  # 添加network组件

  if [[ "$KUBE_NETWORK" == "flannel" ]]; then
    log::info "[network]" "add flannel"
    
    local flannel_file="${OFFLINE_DIR}/manifests/kube-flannel.yml"
    utils::download_file "https://cdn.jsdelivr.net/gh/coreos/flannel@v${FLANNEL_VERSION}/Documentation/kube-flannel.yml" "${flannel_file}"
    
    command::exec "${MGMT_NODE}" "
      sed -i -e 's#10.244.0.0/16#${KUBE_POD_SUBNET}#g' \
             -e 's#quay.io/coreos#${KUBE_IMAGE_REPO}#g' \
             -e 's#\"Type\": \"vxlan\"#\"Type\": \"${KUBE_FLANNEL_TYPE}\"#g' \"${flannel_file}\"
      if [[ \"${KUBE_FLANNEL_TYPE}\" == \"vxlan\" ]]; then
        sed -i 's#\"Type\": \"vxlan\"#\"Type\": \"vxlan\", \"DirectRouting\": true#g' \"${flannel_file}\"
      fi
    "
    check::exit_code "$?" "flannel" "change flannel pod subnet"
    kube::apply "${flannel_file}"
    kube::wait "flannel" "kube-system" "pods" "app=flannel"

  elif [[ "$KUBE_NETWORK" == "calico" ]]; then
    log::info "[network]" "add calico"
    utils::download_file "https://docs.projectcalico.org/v${CALICO_VERSION%.*}/manifests/calico.yaml" "${OFFLINE_DIR}/manifests/calico.yaml"
    utils::download_file "https://docs.projectcalico.org/v${CALICO_VERSION%.*}/manifests/calicoctl.yaml" "${OFFLINE_DIR}/manifests/calicoctl.yaml"
    
    command::exec "${MGMT_NODE}" "
      sed -i \"s#:v.*#:v${CALICO_VERSION}#g\" \"${OFFLINE_DIR}/manifests/calico.yaml\"
      sed -i 's#value: \"Always\"#value: \"CrossSubnet\"#g' \"${OFFLINE_DIR}/manifests/calico.yaml\"
      sed -i \"s#:v.*#:v${CALICO_VERSION}#g\" \"${OFFLINE_DIR}/manifests/calicoctl.yaml\"
    "
    check::exit_code "$?" "network" "change calico version to ${CALICO_VERSION}"
    
    kube::apply "${OFFLINE_DIR}/manifests/calico.yaml"
    kube::apply "${OFFLINE_DIR}/manifests/calicoctl.yaml"
    kube::wait "calico-kube-controllers" "kube-system" "pods" "k8s-app=calico-kube-controllers"
    kube::wait "calico-node" "kube-system" "pods" "k8s-app=calico-node"

  elif [[ "$KUBE_NETWORK" == "cilium" ]]; then 
    log::info "[network]" "add cilium"

    local cilium_file="${OFFLINE_DIR}/manifests/cilium.yml"
    local cilium_hubble_file="${OFFLINE_DIR}/manifests/cilium_hubble.yml"
    utils::download_file "https://cdn.jsdelivr.net/gh/cilium/cilium@${CILIUM_VERSION}/install/kubernetes/quick-install.yaml" "${cilium_file}"
    utils::download_file "https://cdn.jsdelivr.net/gh/cilium/cilium@${CILIUM_VERSION}/install/kubernetes/quick-hubble-install.yaml" "${cilium_hubble_file}"

    local all_node=""
    if [[ "${MASTER_NODES}" == "" && "${WORKER_NODES}" == "" ]]; then 
      command::exec "${MGMT_NODE}" "
        kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {end}'
      "
      get::command_output "all_node" "$?"
    else
      all_node="${MASTER_NODES} ${WORKER_NODES}"
    fi

    for host in $all_node
    do
      command::exec "${host}" "mount bpffs -t bpf /sys/fs/bpf"
      check::exit_code "$?" "network" "${host}: mount bpf filesystem"
    done

    command::exec "${MGMT_NODE}" "
      sed -i \"s#10.0.0.0/8#${KUBE_POD_SUBNET}#g\" \"${cilium_file}\"
    "
    kube::apply "${cilium_file}"
    kube::wait "cilium-node" "kube-system" "pods" "k8s-app=cilium"
    kube::wait "cilium-operator" "kube-system" "pods" "name=cilium-operator"
    kube::apply "${cilium_hubble_file}"
    kube::wait "hubble-relay" "kube-system" "pods" "k8s-app=hubble-relay"

    log::info "[monitor]" "add hubble-ui ingress"
    kube::apply "hubble-ui ingress" "
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hubble-ui
  namespace: kube-system
  annotations:
    kubernetes.io/ingress.class: ${KUBE_INGRESS}
spec:
  rules:
  - host: hubble-ui.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: hubble-ui
            port:
              number: 80
    "
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then                                                                                                                                            
      get::ingress_conn
      log::access "[ingress]" "curl -H 'Host:hubble-ui.cluster.local' http://${INGRESS_CONN}"
    fi
  else
    log::warning "[network]" "No $KUBE_NETWORK config."
  fi
}


function add::addon() {
  # 添加addon组件

  if [[ "$KUBE_ADDON" == "metrics-server" ]]; then
    log::info "[addon]" "download metrics-server manifests"
    local metrics_server_file="${OFFLINE_DIR}/manifests/metrics-server.yml"
    utils::download_file "${GITHUB_PROXY}/https://github.com/kubernetes-sigs/metrics-server/releases/download/v${METRICS_SERVER_VERSION}/components.yaml" "${metrics_server_file}"
  
    command::exec "${MGMT_NODE}" "
      sed -i -e 's#k8s.gcr.io/metrics-server#$KUBE_IMAGE_REPO#g' \
             -e '/--kubelet-preferred-address-types=.*/d' \
             -e 's/\\(.*\\)- --secure-port=\\(.*\\)/\\1- --secure-port=\\2\\n\\1- --kubelet-insecure-tls\\n\\1- --kubelet-preferred-address-types=InternalIP,InternalDNS,ExternalIP,ExternalDNS,Hostname/g' \
             \"${metrics_server_file}\"
    "
    check::exit_code "$?" "addon" "change metrics-server parameter"
    kube::apply "${metrics_server_file}"
  elif [[ "$KUBE_ADDON" == "nodelocaldns" ]]; then
    log::info "[addon]" "download nodelocaldns manifests"
    local nodelocaldns_file="${OFFLINE_DIR}/manifests/nodelocaldns.yaml"
    utils::download_file "https://cdn.jsdelivr.net/gh/kubernetes/kubernetes@master/cluster/addons/dns/nodelocaldns/nodelocaldns.yaml" "${nodelocaldns_file}"
  
    command::exec "${MGMT_NODE}" "
      cluster_dns=\$(kubectl -n kube-system get svc kube-dns -o jsonpath={.spec.clusterIP})
      sed -i -e \"s#k8s.gcr.io/dns#${KUBE_IMAGE_REPO}#g\" \
             -e \"s/__PILLAR__CLUSTER__DNS__/\$cluster_dns/g\" \
             -e \"s/__PILLAR__UPSTREAM__SERVERS__/\$cluster_dns/g\" \
             -e \"s/__PILLAR__LOCAL__DNS__/169.254.20.10/g\" \
             -e \"s/[ |,]__PILLAR__DNS__SERVER__//g\" \
             -e \"s/__PILLAR__DNS__DOMAIN__/$KUBE_DNSDOMAIN/g\" \
             \"${nodelocaldns_file}\"
    "
    check::exit_code "$?" "addon" "change nodelocaldns parameter"
    kube::apply "${nodelocaldns_file}"
  else
    log::warning "[addon]" "No $KUBE_ADDON config."
  fi
}


function add::monitor() {
  # 添加监控组件
  
  if [[ "$KUBE_MONITOR" == "prometheus" ]]; then
    log::info "[monitor]" "add prometheus"
    utils::download_file "${GITHUB_PROXY}https://github.com/prometheus-operator/kube-prometheus/archive/v${KUBE_PROMETHEUS_VERSION}.zip" "${OFFLINE_DIR}/manifests/prometheus.zip" "unzip"
   
    log::info "[monitor]" "apply prometheus manifests"
    command::exec "${MGMT_NODE}" "
      $(declare -f utils::retry)
      cd \"${OFFLINE_DIR}/manifests/kube-prometheus-${KUBE_PROMETHEUS_VERSION}\" \
      && utils::retry 6 kubectl apply --wait=true --timeout=10s -f manifests/setup/ \
      && until kubectl get servicemonitors --all-namespaces ; do date; sleep 1; echo ''; done \
      && utils::retry 6 kubectl apply --wait=true --timeout=10s -f manifests/
    "
    check::exit_code "$?" "apply" "add prometheus"
    kube::wait "prometheus" "monitoring" "pods --all"

    kube::apply "controller-manager and scheduler prometheus discovery service" "
---
apiVersion: v1
kind: Service
metadata:
  namespace: kube-system
  name: kube-scheduler-prometheus-discovery
  labels:
    k8s-app: kube-scheduler
spec:
  selector:
    component: kube-scheduler
  type: ClusterIP
  clusterIP: None
  ports:
  - name: https-metrics
    port: 10259
    targetPort: 10259
    protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  namespace: kube-system
  name: kube-controller-manager-prometheus-discovery
  labels:
    k8s-app: kube-controller-manager
spec:
  selector:
    component: kube-controller-manager
  type: ClusterIP
  clusterIP: None
  ports:
  - name: https-metrics
    port: 10257
    targetPort: 10257
    protocol: TCP
    "
    
    log::info "[monitor]" "add prometheus ingress"
    kube::apply "prometheus ingress" "
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana
  namespace: monitoring
  annotations:
    kubernetes.io/ingress.class: ${KUBE_INGRESS}
spec:
  rules:
  - host: grafana.monitoring.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: grafana
            port:
              number: 3000
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prometheus
  namespace: monitoring
  annotations:
    kubernetes.io/ingress.class: ${KUBE_INGRESS}
spec:
  rules:
  - host: prometheus.monitoring.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prometheus-k8s
            port:
              number: 9090
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: alertmanager
  namespace: monitoring
  annotations:
    kubernetes.io/ingress.class: ${KUBE_INGRESS}
spec:
  rules:
  - host: alertmanager.monitoring.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: alertmanager-main
            port:
              number: 9093
    "
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then
      get::ingress_conn
      log::access "[ingress]" "curl -H 'Host:grafana.monitoring.cluster.local' http://${INGRESS_CONN}; auth: admin/admin"
      log::access "[ingress]" "curl -H 'Host:prometheus.monitoring.cluster.local' http://${INGRESS_CONN}"
      log::access "[ingress]" "curl -H 'Host:alertmanager.monitoring.cluster.local' http://${INGRESS_CONN}"
    fi
    
  else
    log::warning "[addon]" "No $KUBE_MONITOR config."
  fi
}


function add::log() {
  # 添加log组件

  if [[ "$KUBE_LOG" == "elasticsearch" ]]; then
    log::info "[log]" "add elasticsearch"
    kube::apply "elasticsearch" "
---
kind: Namespace
apiVersion: v1
metadata:
  name: kube-logging
---
kind: Service
apiVersion: v1
metadata:
  name: elasticsearch
  namespace: kube-logging
  labels:
    app: elasticsearch
spec:
  selector:
    app: elasticsearch
  clusterIP: None
  ports:
    - port: 9200
      name: rest
    - port: 9300
      name: inter-node
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: es-cluster
  namespace: kube-logging
spec:
  serviceName: elasticsearch
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - {key: app,operator: In,values: [\"elasticsearch\"]}
              topologyKey: kubernetes.io/hostname
      containers:
      - name: elasticsearch
        image: ${KUBE_IMAGE_REPO}/elasticsearch:${ELASTICSEARCH_VERSION}
        resources:
            limits:
              cpu: 1000m
            requests:
              cpu: 100m
        ports:
        - containerPort: 9200
          name: rest
          protocol: TCP
        - containerPort: 9300
          name: inter-node
          protocol: TCP
        volumeMounts:
        - name: data
          mountPath: /usr/share/elasticsearch/data
        env:
          - name: cluster.name
            value: k8s-logs
          - name: node.name
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: discovery.seed_hosts
            value: 'es-cluster-0.elasticsearch,es-cluster-1.elasticsearch,es-cluster-2.elasticsearch'
          - name: cluster.initial_master_nodes
            value: 'es-cluster-0,es-cluster-1,es-cluster-2'
          - name: discovery.zen.minimum_master_nodes
            value: '2'
          - name: ES_JAVA_OPTS
            value: '-Xms512m -Xmx512m'
      volumes:
      - name: data
        hostPath:
          path: /var/lib/elasticsearch
          type: DirectoryOrCreate
      initContainers:
      - name: fix-permissions
        image: alpine:3.9
        command: ['sh', '-c', 'chown -R 1000:1000 /usr/share/elasticsearch/data']
        securityContext:
          privileged: true
        volumeMounts:
        - name: data
          mountPath: /usr/share/elasticsearch/data
      - name: increase-vm-max-map
        image: alpine:3.9
        command: ['sysctl', '-w', 'vm.max_map_count=262144']
        securityContext:
          privileged: true
      - name: increase-fd-ulimit
        image: alpine:3.9
        command: ['sh', '-c', 'ulimit -n 65536']
        securityContext:
          privileged: true
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elasticsearch
  namespace: kube-logging
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
  - host: elasticsearch.logging.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: elasticsearch
            port:
              number: 9200
---
apiVersion: v1
kind: Service
metadata:
  name: kibana
  namespace: kube-logging
  labels:
    app: kibana
spec:
  ports:
  - port: 5601
  selector:
    app: kibana

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kibana
  namespace: kube-logging
  labels:
    app: kibana
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kibana
  template:
    metadata:
      labels:
        app: kibana
    spec:
      containers:
      - name: kibana
        image: ${KUBE_IMAGE_REPO}/kibana:${ELASTICSEARCH_VERSION}
        resources:
          limits:
            cpu: 1000m
          requests:
            cpu: 100m
        env:
          - name: ELASTICSEARCH_URL
            value: http://elasticsearch:9200
        ports:
        - containerPort: 5601
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kibana
  namespace: kube-logging
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
  - host: kibana.logging.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kibana
            port:
              number: 5601
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluentd
  namespace: kube-logging
  labels:
    app: fluentd
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fluentd
  labels:
    app: fluentd
rules:
- apiGroups:
  - ''
  resources:
  - pods
  - namespaces
  verbs:
  - get
  - list
  - watch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: fluentd
roleRef:
  kind: ClusterRole
  name: fluentd
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: fluentd
  namespace: kube-logging
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: kube-logging
  labels:
    app: fluentd
spec:
  selector:
    matchLabels:
      app: fluentd
  template:
    metadata:
      labels:
        app: fluentd
    spec:
      serviceAccount: fluentd
      serviceAccountName: fluentd
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1.14.3-debian-elasticsearch7-1.0
        env:
          - name:  FLUENT_ELASTICSEARCH_HOST
            value: elasticsearch.kube-logging.svc.${KUBE_DNSDOMAIN}
          - name:  FLUENT_ELASTICSEARCH_PORT
            value: '9200'
          - name: FLUENT_ELASTICSEARCH_SCHEME
            value: http
          - name: FLUENTD_SYSTEMD_CONF
            value: disable
        resources:
          limits:
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
    " 
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then
      kube::wait "elasticsearch" "kube-logging" "pods --all"
      get::ingress_conn
      log::access "[ingress]" "curl -H 'Host:kibana.logging.cluster.local' http://${INGRESS_CONN}"
      log::access "[ingress]" "curl -H 'Host:elasticsearch.logging.cluster.local' http://${INGRESS_CONN}"
    fi
  else
    log::warning "[log]" "No $KUBE_LOG config."
  fi
}


function add::storage() {
  # 添加存储 

  if [[ "$KUBE_STORAGE" == "rook" ]]; then

    log::info "[storage]" "add rook"
    utils::download_file "${GITHUB_PROXY}https://github.com/rook/rook/archive/v${ROOK_VERSION}.zip" "${OFFLINE_DIR}/manifests/rook-${ROOK_VERSION}.zip" "unzip"

    kube::apply "${OFFLINE_DIR}/manifests/rook-${ROOK_VERSION}/cluster/examples/kubernetes/ceph/common.yaml"
    kube::apply "${OFFLINE_DIR}/manifests/rook-${ROOK_VERSION}/cluster/examples/kubernetes/ceph/operator.yaml"
    kube::apply "${OFFLINE_DIR}/manifests/rook-${ROOK_VERSION}/cluster/examples/kubernetes/ceph/cluster.yaml"

  elif [[ "$KUBE_STORAGE" == "longhorn" ]]; then
    log::info "[storage]" "add longhorn"
    log::info "[storage]" "get cluster node hosts"
    if [[ "${ADD_TAG:-}" == "1" ]]; then
      command::exec "${MGMT_NODE}" "
        kubectl get node -o jsonpath='{\$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
      "
      get::command_output "cluster_nodes" "$?" "exit"
    else
      cluster_nodes="${MASTER_NODES} ${WORKER_NODES}"
    fi
    for host in ${cluster_nodes:-}
    do
      log::info "[storage]"  "${host}: install iscsi-initiator-utils"
      command::exec "${host}" "
        apt-get install -y open-iscsi
      "
      check::exit_code "$?" "storage" "${host}: install iscsi-initiator-utils" "exit"
    done
    
    local longhorn_file="${OFFLINE_DIR}/manifests/longhorn.yaml"
    utils::download_file "https://cdn.jsdelivr.net/gh/longhorn/longhorn@v${LONGHORN_VERSION}/deploy/longhorn.yaml" "${longhorn_file}"

    command::exec "${MGMT_NODE}" "
      sed -i 's#numberOfReplicas: \"3\"#numberOfReplicas: \"1\"#g' \"${longhorn_file}\"
    "
    check::exit_code "$?" "storage" "set longhorn numberOfReplicas is 1"

    kube::apply "${longhorn_file}"
    kube::wait "longhorn" "longhorn-system" "pods --all"
    
    log::info "[storage]"  "set longhorn is default storage class"
    command::exec "${MGMT_NODE}" "
      default_class=\"\$(kubectl get storageclass -A -o jsonpath='{.items[?(@.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class==\\\"true\\\")].metadata.name}')\"
      if [ \"\${default_class:-}\" != \"\" ]; then
         kubectl patch storageclass \${default_class} -p '{\"metadata\": {\"annotations\":{\"storageclass.kubernetes.io/is-default-class\":\"false\"}}}'
      fi
      kubectl patch storageclass longhorn -p '{\"metadata\": {\"annotations\":{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}'
    "
    check::exit_code "$?" "storage" "set longhorn is default storage class"
    
    kube::apply "longhorn ingress" "
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: longhorn-ingress
  namespace: longhorn-system
spec:
  rules:
  - host: longhorn.storage.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: longhorn-frontend
            port:
              number: 80
    "
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then
      get::ingress_conn
      log::access "[ingress]" "curl -H 'Host:longhorn.storage.cluster.local' http://${INGRESS_CONN}"
    fi
  else
    log::warning "[storage]" "No $KUBE_STORAGE config."
  fi
}


function add::ui() {
  # 添加用户界面

  if [[ "$KUBE_UI" == "dashboard" ]]; then
    log::info "[ui]" "add kubernetes dashboard"
    local dashboard_file="${OFFLINE_DIR}/manifests/kubernetes-dashboard.yml"
    utils::download_file "https://cdn.jsdelivr.net/gh/kubernetes/dashboard@v${KUBERNETES_DASHBOARD_VERSION}/aio/deploy/recommended.yaml" "${dashboard_file}"
    kube::apply "${dashboard_file}"
    kube::apply "kubernetes dashboard ingress" "
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: ${KUBE_INGRESS}
$( if [[ $KUBE_INGRESS == "nginx" ]]; then
echo """
    nginx.ingress.kubernetes.io/secure-backends: 'true'
    nginx.ingress.kubernetes.io/backend-protocol: 'HTTPS'
    nginx.ingress.kubernetes.io/ssl-passthrough: 'true'
""";
elif [[ $KUBE_INGRESS == "traefik" ]]; then 
echo """
    traefik.ingress.kubernetes.io/frontend-entry-points: https
    traefik.ingress.kubernetes.io/auth-type: 'basic'
    traefik.ingress.kubernetes.io/auth-secret: 'kubernetes-dashboard-auth'
    traefik.ingress.kubernetes.io/ssl-redirect: 'true'
""";
fi
)
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard 
spec:
$( if [[ $KUBE_INGRESS == "nginx" ]]; then
echo """
  tls:
  - hosts:
    - kubernetes-dashboard.cluster.local
    secretName: kubernetes-dashboard-certs
"""
elif [[ $KUBE_INGRESS == "traefik" ]]; then 
echo """
"""
fi
)
  rules:
  - host: kubernetes-dashboard.cluster.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes-dashboard
            port:
              number: 443
    "
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then
      get::ingress_conn "443"
      log::access "[ingress]" "curl --insecure -H 'Host:kubernetes-dashboard.cluster.local' https://${INGRESS_CONN}"

      command::exec "${MGMT_NODE}" "
        kubectl create serviceaccount kubernetes-dashboard-admin-sa -n kubernetes-dashboard
        kubectl create clusterrolebinding kubernetes-dashboard-admin-sa --clusterrole=cluster-admin --serviceaccount=kubernetes-dashboard:kubernetes-dashboard-admin-sa -n kubernetes-dashboard
      "
      local s="$?"
      check::exit_code "$s" "ui" "create kubernetes dashboard admin service account"
      local dashboard_token=""
      command::exec "${MGMT_NODE}" "
        kubectl describe secrets \$(kubectl describe sa kubernetes-dashboard-admin-sa -n kubernetes-dashboard | awk '/Tokens/ {print \$2}') -n kubernetes-dashboard | awk '/token:/{print \$2}'
      "
      get::command_output "dashboard_token" "$?"
      [[ "$dashboard_token" != "" ]] && log::access "[Token]" "${dashboard_token}"
    fi
  elif [[ "$KUBE_UI" == "kubesphere" ]]; then
    log::info "[ui]" "add kubesphere"
    utils::download_file "https://cdn.jsdelivr.net/gh/kubesphere/ks-installer@v${KUBESPHERE_VERSION}/deploy/kubesphere-installer.yaml" "${OFFLINE_DIR}/manifests/kubesphere-installer.yaml"
    utils::download_file "https://cdn.jsdelivr.net/gh/kubesphere/ks-installer@v${KUBESPHERE_VERSION}/deploy/cluster-configuration.yaml" "${OFFLINE_DIR}/manifests/cluster-configuration.yaml"
    kube::apply "${OFFLINE_DIR}/manifests/kubesphere-installer.yaml"
    kube::apply "${OFFLINE_DIR}/manifests/cluster-configuration.yaml"

    sleep 60
    kube::wait "ks-installer" "kubesphere-system" "pods" "app=ks-install"
    command::exec "${MGMT_NODE}" "
      $(declare -f utils::retry) 
      utils::retry 10 kubectl -n kubesphere-system get pods redis-ha-server-0
      kubectl -n kubesphere-system get sts redis-ha-server -o yaml | sed 's#node-role.kubernetes.io/master#node-role.kubernetes.io/worker#g' | kubectl replace --force -f -
      utils::retry 10 kubectl -n kubesphere-system get pods openldap-0
      kubectl -n kubesphere-system get sts openldap -o yaml | sed 's#node-role.kubernetes.io/master#node-role.kubernetes.io/worker#g' | kubectl replace --force -f -
    "
    check::exit_code "$?" "ui" "set statefulset to worker node"

    sleep 60
    kube::wait "kubesphere-system" "kubesphere-system" "pods --all"
    kube::wait "kubesphere-controls-system" "kubesphere-controls-system" "pods --all" 
    kube::wait "kubesphere-monitoring-system" "kubesphere-monitoring-system" "pods --all" 
    # shellcheck disable=SC2181
    if [[ "$?" == "0" ]]; then
      command::exec "${MGMT_NODE}" "
        kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address } {end}' | awk '{print \$1}'
      "
      get::command_output "node_ip" "$?"
      log::access "[service]" "curl http://${node_ip:-NodeIP}:30880;  auth: admin/P@88w0rd"
    fi
  else
    log::warning "[ui]" "No $KUBE_UI config."
  fi
}


function add::ops() {
  # 运维操作
   
  local master_num
  master_num=$(awk '{print NF}' <<< "${MASTER_NODES}")
  
  log::info "[ops]" "add anti-affinity strategy to coredns"
  command::exec "${MGMT_NODE}" """
    kubectl -n kube-system patch deployment coredns --patch '{\"spec\": {\"template\": {\"spec\": {\"affinity\":{\"podAntiAffinity\":{\"preferredDuringSchedulingIgnoredDuringExecution\":[{\"weight\":100,\"podAffinityTerm\":{\"labelSelector\":{\"matchExpressions\":[{\"key\":\"k8s-app\",\"operator\":\"In\",\"values\":[\"kube-dns\"]}]},\"topologyKey\":\"kubernetes.io/hostname\"}}]}}}}}}' --record
  """
  check::exit_code "$?" "ops" "add anti-affinity strategy to coredns"

  log::info "[ops]" "add etcd snapshot cronjob"
  command::exec "${MGMT_NODE}" "
    kubeadm config images list --config=/etc/kubernetes/kubeadmcfg.yaml 2>/dev/null | grep etcd:
  "
  get::command_output "etcd_image" "$?"
  command::exec "${MGMT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/master' --no-headers | wc -l
  "
  get::command_output "master_num" "$?"

  [[ "${master_num:-0}" == "0" ]] && master_num=1
  kube::apply "etcd-snapshot" """
---
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: etcd-snapshot
  namespace: kube-system
spec:
  schedule: '0 */6 * * *'
  successfulJobsHistoryLimit: 3
  suspend: false
  concurrencyPolicy: Allow
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 6
      parallelism: ${master_num}
      completions: ${master_num}
      template:
        metadata:
          labels:
            app: etcd-snapshot
        spec:
          affinity:
            podAntiAffinity:
              requiredDuringSchedulingIgnoredDuringExecution:
              - labelSelector:
                  matchExpressions:
                  - key: app
                    operator: In
                    values:
                    - etcd-snapshot
                topologyKey: 'kubernetes.io/hostname'
          containers:
          - name: etcd-snapshot
            image: ${etcd_image:-${KUBE_IMAGE_REPO}/etcd:3.4.13-0}
            imagePullPolicy: IfNotPresent
            args:
            - -c
            - etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt
              --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt --key=/etc/kubernetes/pki/etcd/healthcheck-client.key
              snapshot save /backup/etcd-snapshot-\\\\\\\$(date +%Y-%m-%d_%H:%M:%S_%Z).db
              && echo 'delete old backups' && find /backup -type f -mtime +30 -exec rm -fv {} \\; || echo error
            command:
            - /bin/sh
            env:
            - name: ETCDCTL_API
              value: '3'
            resources: {}
            terminationMessagePath: /dev/termination-log
            terminationMessagePolicy: File
            volumeMounts:
            - name: etcd-certs
              mountPath: /etc/kubernetes/pki/etcd
              readOnly: true
            - name: backup
              mountPath: /backup
            - name: etc
              mountPath: /etc
            - name: bin
              mountPath: /usr/bin
            - name: lib64
              mountPath: /lib64
          dnsPolicy: ClusterFirst
          hostNetwork: true
          nodeSelector:
            node-role.kubernetes.io/master: ''
          tolerations:
          - effect: NoSchedule
            operator: Exists
          restartPolicy: OnFailure
          schedulerName: default-scheduler
          securityContext: {}
          terminationGracePeriodSeconds: 30
          volumes:
          - name: etcd-certs
            hostPath:
              path: /etc/kubernetes/pki/etcd
              type: DirectoryOrCreate
          - name: backup
            hostPath:
              path: /var/lib/etcd/backups
              type: DirectoryOrCreate
          - name: etc
            hostPath:
              path: /etc
          - name: bin
            hostPath:
              path: /usr/bin
          - name: lib64
            hostPath:
              path: /lib64
"""
  # shellcheck disable=SC2181
  [[ "$?" == "0" ]] && log::access "[ops]" "etcd backup directory: /var/lib/etcd/backups"
  command::exec "${MGMT_NODE}" "
    jobname=\"etcd-snapshot-$(date +%s)\"
    kubectl create job --from=cronjob/etcd-snapshot \${jobname} -n kube-system && \
    kubectl wait --for=condition=complete job/\${jobname} -n kube-system
  "
  check::exit_code "$?" "ops" "trigger etcd backup"
}


function reset::node() {
  # 重置节点

  local host=$1
  log::info "[reset]" "node $host"
  command::exec "${host}" "
    set +ex
    cri_socket=\"\"
    [ -S /var/run/crio/crio.sock ] && cri_socket=\"--cri-socket /var/run/crio/crio.sock\"
    [ -S /run/containerd/containerd.sock ] && cri_socket=\"--cri-socket /run/containerd/containerd.sock\"
    kubeadm reset -f \$cri_socket
    [ -f \"\$(which kubelet)\" ] && { systemctl stop kubelet; find /var/lib/kubelet | xargs -n 1 findmnt -n -o TARGET -T | sort | uniq | xargs -r umount -v; apt remove -y kubeadm kubelet kubectl; }
    [ -d /etc/kubernetes ] && rm -rf /etc/kubernetes/* /var/lib/kubelet/* /var/lib/etcd/* \$HOME/.kube /etc/cni/net.d/* /var/lib/dockershim/* /var/lib/cni/* /var/run/kubernetes/*

    [ -f \"\$(which docker)\" ] && { docker rm -f -v \$(docker ps | grep kube | awk '{print \$1}'); systemctl stop docker; rm -rf \$HOME/.docker /etc/docker/* /var/lib/docker/*; apt remove -y docker; }
    [ -f \"\$(which containerd)\" ] && { crictl rm \$(crictl ps -a -q); systemctl stop containerd; rm -rf /etc/containerd/* /var/lib/containerd/*; apt remove -y containerd.io; }
    [ -f \"\$(which crio)\" ] && { crictl rm \$(crictl ps -a -q); systemctl stop crio; rm -rf /etc/crictl.yaml /etc/crio/* /var/run/crio/*; apt remove -y cri-o; }
    [ -f \"\$(which runc)\" ] && { find /run/containers/ /var/lib/containers/ | xargs -n 1 findmnt -n -o TARGET -T | sort | uniq | xargs -r umount -v; rm -rf /var/lib/containers/* /var/run/containers/*; apt remove -y runc; }
    [ -f \"\$(which haproxy)\" ] && { systemctl stop haproxy; rm -rf /etc/haproxy/*; apt remove -y haproxy; }

    sed -i -e \"/$KUBE_APISERVER/d\" -e '/-worker-/d' -e '/-master-/d' /etc/hosts
    sed -i '/## Kainstall managed start/,/## Kainstall managed end/d' /etc/security/limits.conf /etc/systemd/system.conf /etc/bash.bashrc /etc/audit/rules.d/audit.rules
    
    [ -d /var/lib/elasticsearch ] && rm -rf /var/lib/elasticsearch/*
    [ -d /var/lib/longhorn ] &&  rm -rf /var/lib/longhorn/*
    [ -d \"${OFFLINE_DIR:-/tmp/abc}\" ] && rm -rf \"${OFFLINE_DIR:-/tmp/abc}\"

    ipvsadm --clear
    iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
    for int in kube-ipvs0 cni0 docker0 dummy0 flannel.1 cilium_host cilium_net cilium_vxlan lxc_health nodelocaldns 
    do
      [ -d /sys/class/net/\${int} ] && ip link delete \${int}
    done
    modprobe -r ipip
    echo done.
  "
  check::exit_code "$?" "reset" "$host: reset"
}


function reset::cluster() {
  # 重置所有节点
  
  local all_node=""
  
  command::exec "${MGMT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {end}'
  "
  get::command_output "all_node" "$?"
  
  all_node=$(echo "${WORKER_NODES} ${MASTER_NODES} ${all_node}" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')

  for host in $all_node
  do
    reset::node "$host"
  done

}


function offline::load() {
  # 节点加载离线包
 
  local role="${1:-}"
  local hosts=""
  
  if [[ "${role}" == "master" ]]; then
     hosts="${MASTER_NODES}"
  elif [[ "${role}" == "worker" ]]; then
     hosts="${WORKER_NODES}"
  fi
 
  for host in ${hosts}
  do
    log::info "[offline]" "${role} ${host}: load offline file"
    command::exec "${host}"  "[[ ! -d \"${OFFLINE_DIR}\" ]] && { mkdir -pv \"${OFFLINE_DIR}\"; chmod 777 \"${OFFLINE_DIR}\"; } ||:"
    check::exit_code "$?" "offline" "$host: mkdir offline dir" "exit"

    if [[ "${UPGRADE_KERNEL_TAG:-}" == "1" ]]; then
      command::scp "${host}" "${TMP_DIR}/packages/kernel/*" "${OFFLINE_DIR}"
      check::exit_code "$?" "offline" "scp kernel file to $host" "exit"
    else
      log::info "[offline]" "${role} ${host}: copy offline file"
      command::scp "${host}" "${TMP_DIR}/packages/kubeadm/*" "${OFFLINE_DIR}"
      check::exit_code "$?" "offline" "scp kube file to $host" "exit"
      command::scp "${host}" "${TMP_DIR}/packages/all/*" "${OFFLINE_DIR}"
      check::exit_code "$?" "offline" "scp all file to $host" "exit"

      if [[ "${role}" == "worker" ]]; then
        command::scp "${host}" "${TMP_DIR}/packages/worker/*" "${OFFLINE_DIR}"
        check::exit_code "$?" "offline" "scp worker file to $host" "exit"
      fi 

      command::scp "${host}" "${TMP_DIR}/images/${role}.tgz" "${OFFLINE_DIR}"
      check::exit_code "$?" "offline" "scp ${role} images to $host" "exit"
      command::scp "${host}" "${TMP_DIR}/images/all.tgz" "${OFFLINE_DIR}"
      check::exit_code "$?" "offline" "scp all images to $host" "exit"
    fi

    
    log::info "[offline]" "${role} ${host}: install package"
    command::exec "${host}" "dpkg --force-all -i ${OFFLINE_DIR}/*.deb; DEBIAN_FRONTEND=noninteractive apt-get install -f -q -y"
    check::exit_code "$?" "offline" "${role} ${host}: install package" "exit"
  
    if [[ "${UPGRADE_KERNEL_TAG:-}" != "1" ]]; then
      command::exec "${host}" "
        set -e
        for target in firewalld python-firewall firewalld-filesystem iptables; do
          systemctl stop \$target &>/dev/null || true
          systemctl disable \$target &>/dev/null || true
        done
        systemctl start docker && \
        cd ${OFFLINE_DIR} && \
        gzip -d -c ${1}.tgz | docker load && gzip -d -c all.tgz | docker load
      "
      check::exit_code "$?" "offline" "$host: load images" "exit"  
    fi
    command::exec "${host}" "rm -rf ${OFFLINE_DIR:-/tmp/abc}"
    check::exit_code "$?" "offline" "$host: clean offline file"  
  done

  command::scp "${MGMT_NODE}" "${TMP_DIR}/manifests" "${OFFLINE_DIR}"
  check::exit_code "$?" "offline" "scp manifests file to ${MGMT_NODE}" "exit"

  command::scp "${MGMT_NODE}" "${TMP_DIR}/bins" "${OFFLINE_DIR}"
  check::exit_code "$?" "offline" "scp bins file to ${MGMT_NODE}" "exit"
}


function offline::cluster() {
  # 集群节点加载离线包

  [ ! -f "${OFFLINE_FILE}" ] && { log::error "[offline]" "not found ${OFFLINE_FILE}" ; exit 1; }

  log::info "[offline]" "Unzip offline package on local."
  tar zxf "${OFFLINE_FILE}"  -C "${TMP_DIR}/"
  check::exit_code "$?" "offline"  "Unzip offline package"
 
  offline::load "master"
  offline::load "worker"
}


function init::cluster() {
  # 初始化集群

  MGMT_NODE=$(echo "${MASTER_NODES}" | awk '{print $1}')

  # 加载离线包
  [[ "${OFFLINE_TAG:-}" == "1" ]] && offline::cluster
  
  # 1. 初始化节点
  init::node
  # 2. 安装包
  install::package
  # 3. 初始化kubeadm
  kubeadm::init
  # 4. 加入集群
  kubeadm::join
  # 5. 添加network
  add::network
  # 6. 安装addon
  add::addon
  # 7. 添加ingress
  add::ingress
  # 8. 添加storage
  [[ "${STORAGE_TAG:-}" == "1" ]] && add::storage
  # 9. 添加web ui
  add::ui
  # 10. 添加monitor
  [[ "${MONITOR_TAG:-}" == "1" ]] && add::monitor
  # 11. 添加log
  [[ "${LOG_TAG:-}" == "1" ]] && add::log
  # 12. 运维操作
  add::ops
  # 13. 查看集群状态
  kube::status
}


function add::node() {
  # 添加节点
  
  # 加载离线包
  [[ "${OFFLINE_TAG:-}" == "1" ]] && offline::cluster

  # KUBE_VERSION未指定时，获取集群的版本
  if [[ "${KUBE_VERSION}" == "" || "${KUBE_VERSION}" == "latest" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.nodeInfo.kubeletVersion } {end}' | awk -F'v| ' '{print \$2}'
  "
    get::command_output "KUBE_VERSION" "$?" "exit"
  fi

  # 1. 初始化节点
  init::add_node
  # 2. 安装包
  install::package
  # 3. 加入集群
  kubeadm::join
  # 4. haproxy添加apiserver
  config::haproxy_backend "add"
  # 5. 更新 etcd snapshot 副本
  config::etcd_snapshot
  # 6. 查看集群状态
  kube::status
}


function del::node() {
  # 删除节点
 
  config::haproxy_backend "remove"

  local cluster_nodes=""
  local del_hosts_cmd=""
  command::exec "${MGMT_NODE}" "
     kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {.metadata.name }\\n{end}'
  "
  get::command_output "cluster_nodes" "$?" exit

  for host in $MASTER_NODES
  do
     command::exec "${MGMT_NODE}" "
       etcd_pod=\$(kubectl -n kube-system get pods -l component=etcd --field-selector=status.phase=Running -o jsonpath='{\$.items[0].metadata.name}')
       etcd_node=\$(kubectl -n kube-system exec \$etcd_pod -- sh -c \"export ETCDCTL_API=3 ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt ETCDCTL_CERT=/etc/kubernetes/pki/etcd/server.crt ETCDCTL_KEY=/etc/kubernetes/pki/etcd/server.key ETCDCTL_ENDPOINTS=https://127.0.0.1:2379; etcdctl member list\"| grep $host | awk -F, '{print \$1}')
       echo \"\$etcd_pod \$etcd_node\"
       kubectl -n kube-system exec \$etcd_pod -- sh -c \"export ETCDCTL_API=3 ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt ETCDCTL_CERT=/etc/kubernetes/pki/etcd/server.crt ETCDCTL_KEY=/etc/kubernetes/pki/etcd/server.key ETCDCTL_ENDPOINTS=https://127.0.0.1:2379; etcdctl member remove \$etcd_node; etcdctl member list\"
     "
     check::exit_code "$?" "del" "remove $host etcd member"
  done

  for host in $MASTER_NODES $WORKER_NODES
  do
    log::info "[del]" "node $host"

    local node_name; node_name=$(echo -ne "${cluster_nodes}" | grep "${host}" | awk '{print $2}')
    if [[ "${node_name}" == "" ]]; then
      log::warning "[del]" "node $host not found."
      read -r -t 10 -n 1 -p "Do you need to reset the node (y/n)? " answer
      [[ -z "$answer" || "$answer" != "y" ]] && exit || echo
    else
      log::info "[del]" "drain $host"
      command::exec "${MGMT_NODE}" "kubectl drain $node_name --force --ignore-daemonsets --delete-local-data"
      check::exit_code "$?" "del" "$host: drain"

      log::info "[del]" "delete node $host"
      command::exec "${MGMT_NODE}" "kubectl delete node $node_name"
      check::exit_code "$?" "del" "$host: delete"
      sleep 3
    fi
    reset::node "$host"
    del_hosts_cmd="${del_hosts_cmd}\nsed -i "/$host/d" /etc/hosts"
  done

  for host in $(echo -ne "${cluster_nodes}" | awk '{print $1}')
  do
     log::info "[del]" "$host: remove del node hostname resolution"
     command::exec "${host}" "
       $(echo -ne "${del_hosts_cmd}")
     "
     check::exit_code "$?" "del" "remove del node hostname resolution"
  done
  [ "$MASTER_NODES" != "" ] && config::etcd_snapshot
  kube::status
}


function upgrade::cluster() {
  # 升级集群

  log::info "[upgrade]" "upgrade to $KUBE_VERSION"
  log::info "[upgrade]" "backup cluster"
  add::ops

  local stable_version="2"
  command::exec "127.0.0.1" "wget https://storage.googleapis.com/kubernetes-release/release/stable.txt -q -O -"
  get::command_output "stable_version" "$?" && stable_version="${stable_version#v}"

  local node_hosts="$MASTER_NODES $WORKER_NODES"
  if [[ "$node_hosts" == " " ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node -o jsonpath='{range.items[*]}{.metadata.name } {end}'
    "
    get::command_output "node_hosts" "$?" exit
  fi

  local skip_plan=${SKIP_UPGRADE_PLAN,,}
  for host in ${node_hosts}
  do
    log::info "[upgrade]" "node: $host"
    local local_version=""
    command::exec "${host}" "kubectl version --client --short | awk '{print \$3}'"
    get::command_output "local_version" "$?" && local_version="${local_version#v}"

    if [[ "${KUBE_VERSION}" != "latest" ]]; then
      if [[ "${KUBE_VERSION}" == "${local_version}" ]];then
        log::warning "[check]" "The specified version(${KUBE_VERSION}) is consistent with the local version(${local_version})!"
        continue
      fi

      if [[ $(utils::version_to_number "$KUBE_VERSION") -lt $(utils::version_to_number "${local_version}") ]];then
        log::warning "[check]" "The specified version($KUBE_VERSION) is less than the local version(${local_version})!"
        continue
      fi

      if [[ $(utils::version_to_number "$KUBE_VERSION") -gt $(utils::version_to_number "${stable_version}") ]];then
        log::warning "[check]" "The specified version($KUBE_VERSION) is more than the stable version(${stable_version})!"
        continue
      fi
    else
      if [[ $(utils::version_to_number "${local_version}") -ge $(utils::version_to_number "${stable_version}") ]];then
        log::warning "[check]" "The local version($local_version) is greater or equal to the stable version(${stable_version})!"
        continue
      fi
    fi

    command::exec "${MGMT_NODE}" "kubectl drain ${host} --ignore-daemonsets --delete-local-data"
    check::exit_code "$?" "upgrade" "drain ${host} node" "exit"
    sleep 5

    if [[ "${skip_plan}" == "false" ]]; then
      command::exec "${host}" "$(declare -f script::upgrage_kube); script::upgrage_kube 'init' '$KUBE_VERSION'"
      check::exit_code "$?" "upgrade" "plan and upgrade cluster on ${host}" "exit"
      command::exec "${host}" "$(declare -f utils::retry); utils::retry 10 kubectl get node"
      check::exit_code "$?" "upgrade" "${host}: upgrade" "exit"
      skip_plan=true
    else
      command::exec "${host}" "$(declare -f script::upgrage_kube); script::upgrage_kube 'node' '$KUBE_VERSION'"
      check::exit_code "$?" "upgrade" "upgrade ${host} node" "exit"
    fi

    command::exec "${MGMT_NODE}" "kubectl wait --for=condition=Ready node/${host} --timeout=120s"
    check::exit_code "$?" "upgrade" "${host} ready"
    sleep 5
    command::exec "${MGMT_NODE}" "$(declare -f utils::retry); utils::retry 6 kubectl uncordon ${host}"
    check::exit_code "$?" "upgrade" "uncordon ${host} node"
    sleep 5
  done
  
  kube::status
}


function update::self {
  # 脚本文件更新
  
  log::info "[update]" "download kainstall script to $0"
  command::exec "127.0.0.1" "
    wget --timeout=10 --waitretry=3 --tries=5 --retry-connrefused https://cdn.jsdelivr.net/gh/lework/kainstall@master/kainstall-debian.sh -O /tmp/kainstall-debian.sh || exit 1
    /bin/mv -fv /tmp/kainstall-debian.sh \"$0\"
    chmod +x \"$0\"
  "
  check::exit_code "$?" "update" "kainstall script"
}


function transform::data {
  # 数据处理及限制

  MASTER_NODES=$(echo "${MASTER_NODES}" | tr ',' ' ')
  WORKER_NODES=$(echo "${WORKER_NODES}" | tr ',' ' ')

  if ! utils::is_element_in_array "$KUBE_CRI" docker containerd cri-o ; then
    log::error "[limit]" "$KUBE_CRI is not supported, only [docker,containerd,cri-o]"
    exit 1
  fi

  [[ "$KUBE_CRI" != "docker" && "${OFFLINE_TAG:-}" == "1" ]] && { log::error "[limit]" "$KUBE_CRI is not supported offline, only docker"; exit 1; }
  [[ "$KUBE_CRI" == "containerd" && "${KUBE_CRI_ENDPOINT}" == "/var/run/dockershim.sock" ]] && KUBE_CRI_ENDPOINT="unix:///run/containerd/containerd.sock"
  [[ "$KUBE_CRI" == "cri-o" && "${KUBE_CRI_ENDPOINT}" == "/var/run/dockershim.sock"  ]] && KUBE_CRI_ENDPOINT="unix:///var/run/crio/crio.sock"

  kubelet_nodeRegistration="nodeRegistration:
  criSocket: ${KUBE_CRI_ENDPOINT:-/var/run/dockershim.sock}
  kubeletExtraArgs:
    runtime-cgroups: /system.slice/${KUBE_CRI//-/}.service
    pod-infra-container-image: ${KUBE_IMAGE_REPO}/pause:${PAUSE_VERSION:-3.6}
"
}


function help::usage {
  # 使用帮助
  
  cat << EOF

Install kubernetes cluster using kubeadm.

Usage:
  $(basename "$0") [command]

Available Commands:
  init            Init Kubernetes cluster.
  reset           Reset Kubernetes cluster.
  add             Add nodes to the cluster.
  del             Remove node from the cluster.
  renew-cert      Renew all available certificates.
  upgrade         Upgrading kubeadm clusters.
  update          Update script file.

Flag:
  -m,--master          master node, default: ''
  -w,--worker          work node, default: ''
  -u,--user            ssh user, default: ${SSH_USER}
  -p,--password        ssh password
     --private-key     ssh private key
  -P,--port            ssh port, default: ${SSH_PORT}
  -v,--version         kube version, default: ${KUBE_VERSION}
  -n,--network         cluster network, choose: [flannel,calico,cilium], default: ${KUBE_NETWORK}
  -i,--ingress         ingress controller, choose: [nginx,traefik], default: ${KUBE_INGRESS}
  -ui,--ui             cluster web ui, choose: [dashboard,kubesphere], default: ${KUBE_UI}
  -a,--addon           cluster add-ons, choose: [metrics-server,nodelocaldns], default: ${KUBE_ADDON}
  -M,--monitor         cluster monitor, choose: [prometheus]
  -l,--log             cluster log, choose: [elasticsearch]
  -s,--storage         cluster storage, choose: [rook,longhorn]
     --cri             cri tools, choose: [docker,containerd,cri-o], default: ${KUBE_CRI}
     --cri-version     cri version, default: ${KUBE_CRI_VERSION}
     --cri-endpoint    cri endpoint, default: ${KUBE_CRI_ENDPOINT}
  -U,--upgrade-kernel  upgrade kernel
  -of,--offline-file   specify the offline package file to load
      --10years        the certificate period is 10 years.
      --sudo           sudo mode
      --sudo-user      sudo user
      --sudo-password  sudo user password

Example:
  [init cluster]
  $0 init \\
  --master 192.168.77.130,192.168.77.131,192.168.77.132 \\
  --worker 192.168.77.133,192.168.77.134,192.168.77.135 \\
  --user root \\
  --password 123456 \\
  --version 1.20.4

  [reset cluster]
  $0 reset \\
  --user root \\
  --password 123456

  [add node]
  $0 add \\
  --master 192.168.77.140,192.168.77.141 \\
  --worker 192.168.77.143,192.168.77.144 \\
  --user root \\
  --password 123456 \\
  --version 1.20.4

  [del node]
  $0 del \\
  --master 192.168.77.140,192.168.77.141 \\
  --worker 192.168.77.143,192.168.77.144 \\
  --user root \\
  --password 123456
 
  [other]
  $0 renew-cert --user root --password 123456
  $0 upgrade --version 1.20.4 --user root --password 123456
  $0 update
  $0 add --ingress traefik
  $0 add --monitor prometheus
  $0 add --log elasticsearch
  $0 add --storage rook
  $0 add --ui dashboard
  $0 add --addon nodelocaldns

EOF
  exit 1
}


######################################################################################################
# main
######################################################################################################


[ "$#" == "0" ] && help::usage

while [ "${1:-}" != "" ]; do
  case $1 in
    init  )                 INIT_TAG=1
                            ;;
    reset )                 RESET_TAG=1
                            ;;
    add )                   ADD_TAG=1
                            ;;
    del )                   DEL_TAG=1
                            ;;
    renew-cert )            RENEW_CERT_TAG=1
                            ;;
    upgrade )               UPGRADE_TAG=1
                            ;;
    update )                UPDATE_TAG=1
                            ;;
    -m | --master )         shift
                            MASTER_NODES=${1:-$MASTER_NODES}
                            ;;
    -w | --worker )         shift
                            WORKER_NODES=${1:-$WORKER_NODES}
                            ;;
    -u | --user )           shift
                            SSH_USER=${1:-$SSH_USER}
                            ;;
    -p | --password )       shift
                            SSH_PASSWORD=${1:-$SSH_PASSWORD}
                            ;;
    --private-key )         shift
                            SSH_PRIVATE_KEY=${1:-$SSH_SSH_PRIVATE_KEY}
                            ;;
    -P | --port )           shift
                            SSH_PORT=${1:-$SSH_PORT}
                            ;;
    -v | --version )        shift
                            KUBE_VERSION=${1:-$KUBE_VERSION}
                            ;;
    -n | --network )        shift
                            NETWORK_TAG=1
                            KUBE_NETWORK=${1:-$KUBE_NETWORK}
                            ;;
    -i | --ingress )        shift
                            INGRESS_TAG=1
                            KUBE_INGRESS=${1:-$KUBE_INGRESS}
                            ;;
    -M | --monitor )        shift
                            MONITOR_TAG=1
                            KUBE_MONITOR=${1:-$KUBE_MONITOR}
                            ;;
    -l | --log )            shift
                            LOG_TAG=1
                            KUBE_LOG=${1:-$KUBE_LOG}
                            ;;
    -s | --storage )        shift
                            STORAGE_TAG=1
                            KUBE_STORAGE=${1:-$KUBE_STORAGE}
                            ;;
    -ui | --ui )            shift
                            UI_TAG=1
                            KUBE_UI=${1:-$KUBE_UI}
                            ;;
    -a | --addon )          shift
                            ADDON_TAG=1
                            KUBE_ADDON=${1:-$KUBE_ADDON}
                            ;;
    --cri )                 shift
                            KUBE_CRI=${1:-$KUBE_CRI}
                            ;;
    --cri-version )         shift
                            KUBE_CRI_VERSION=${1:-$KUBE_CRI_VERSION}
                            ;;
    --cri-endpoint )        shift
                            KUBE_CRI_ENDPOINT=${1:-$KUBE_CRI_ENDPOINT}
                            ;;
    -U | --upgrade-kernel ) UPGRADE_KERNEL_TAG=1
                            ;;
    -of | --offline-file )  shift
                            OFFLINE_TAG=1
                            OFFLINE_FILE=${1:-$OFFLINE_FILE}
                            ;;
    --10years )             CERT_YEAR_TAG=1
                            ;;
    --sudo )                SUDO_TAG=1
                            ;;
    --sudo-user )           shift
                            SUDO_USER=${1:-$SUDO_USER}
                            ;;
    --sudo-password )       shift
                            SUDO_PASSWORD=${1:-}
                            ;;
    * )                     help::usage
                            exit 1
  esac
  shift
done

# 开始
log::info "[start]" "bash $0 ${SCRIPT_PARAMETER//${SSH_PASSWORD:-${SUDO_PASSWORD:-}}/zzzzzz}"  

# 数据处理
transform::data

# 预检
check::preflight

# 动作
if [[ "${INIT_TAG:-}" == "1" ]]; then
  [[ "$MASTER_NODES" == "" ]] && MASTER_NODES="127.0.0.1"
  init::cluster
elif [[ "${ADD_TAG:-}" == "1" ]]; then
  [[ "${NETWORK_TAG:-}" == "1" ]] && { add::network; add=1; }
  [[ "${INGRESS_TAG:-}" == "1" ]] && { add::ingress; add=1; }
  [[ "${STORAGE_TAG:-}" == "1" ]] && { add::storage; add=1; }
  [[ "${MONITOR_TAG:-}" == "1" ]] && { add::monitor; add=1; }
  [[ "${LOG_TAG:-}" == "1" ]] && { add::log; add=1; }
  [[ "${UI_TAG:-}" == "1" ]] && { add::ui; add=1; }
  [[ "${ADDON_TAG:-}" == "1" ]] && { add::addon; add=1; }
  [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]] && { add::node; add=1; }
  [[ "${add:-}" != "1" ]] && help::usage
elif [[ "${DEL_TAG:-}" == "1" ]]; then
  if [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]]; then del::node; else help::usage; fi
elif [[ "${RESET_TAG:-}" == "1" ]]; then
  reset::cluster
elif [[ "${RENEW_CERT_TAG:-}" == "1" ]]; then
  cert::renew
elif [[ "${UPGRADE_TAG:-}" == "1" ]]; then
  upgrade::cluster
elif [[ "${UPDATE_TAG:-}" == "1" ]]; then
  update::self
else
  help::usage
fi
