#!/bin/env bash
###################################################################
#Script Name	: kainstall.sh
#Description	: Install kubernetes cluster using kubeadm.
#Update Date    : 2020-09-28
#Author       	: lework
#Email         	: lework@yeah.net
###################################################################


set -o errtrace         # Make sure any error trap is inherited
set -o nounset          # Disallow expansion of unset variables
set -o pipefail         # Use last non-zero exit code in a pipeline


######################################################################################################
# environment configuration
######################################################################################################

# 版本
DOCKER_VERSION="latest"
KUBE_VERSION="latest"
FLANNEL_VERSION="0.12.0"
METRICS_SERVER_VERSION="0.3.7"
INGRESS_NGINX="0.35.0"
TRAEFIK_VERSION="2.3.0"
CALICO_VERSION="3.16.1"
KUBE_PROMETHEUS_VERSION="0.6.0"
ELASTICSEARCH_VERSION="7.9.2"
ROOK_VERSION="1.3.11"
 
# 集群配置
KUBE_APISERVER="apiserver.cluster.local"
KUBE_POD_SUBNET="10.244.0.0/16"
KUBE_SERVICE_SUBNET="10.96.0.0/16"
KUBE_IMAGE_REPO="registry.aliyuncs.com/k8sxio"
KUBE_NETWORK="flannel"
KUBE_INGRESS="nginx"
KUBE_MONITOR="prometheus"
KUBE_STORAGE="rook"
KUBE_LOG="elasticsearch"

# 定义的master和worker节点地址，以逗号分隔
MASTER_NODES=""
WORKER_NODES=""

# 定义在哪个节点上进行设置
INIT_NODE="127.0.0.1"

# 节点的连接信息
SSH_USER="root"
SSH_PASSWORD="123456"
SSH_PORT="22"

# 节点设置
HOSTNAME_PREFIX="k8s"

# 脚本设置
TMP_DIR="$(mktemp -d -t kainstall.XXXXXXXXXX)"
LOG_FILE="${TMP_DIR}/kainstall.log"
SSH_OPTIONS="-o ConnectTimeout=600 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
ERROR_INFO="\n\033[31mERROR Summary: \033[0m\n  "
ACCESS_INFO="\n\033[32mACCESS Summary: \033[0m\n  "
COMMAND_OUTPUT=""
SCRIPT_PARAMETER="$*"


trap 'printf "$ERROR_INFO$ACCESS_INFO"; echo -e "\n\n  See detailed log >>> $LOG_FILE \n\n";exit' 1 2 3 15 EXIT

######################################################################################################
# function
######################################################################################################

function log::err() {
  local item="[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[31mERROR:   \033[0m$*\n"
  ERROR_INFO="${ERROR_INFO}${item}  "
  printf "${item}" | tee -a $LOG_FILE
}

function log::info() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[32mINFO:    \033[0m$*\n" | tee -a $LOG_FILE
}

function log::warning() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[33mWARNING: \033[0m$*\n" | tee -a $LOG_FILE
}

function log::access() {
  ACCESS_INFO="${ACCESS_INFO}$*\n  "
  echo -e "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[32mINFO:    \033[0m$*\n" >> $LOG_FILE
}


function version() {
  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }';
}


function exec_command() {
  # 执行命令

  local host=${1:-}
  shift
  local command="$@"

  if [[ "x${host}" == "x127.0.0.1" ]]; then
    # 本地执行
    echo "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: INFO: [exec] \"${command}\"" >> $LOG_FILE
    COMMAND_OUTPUT=$(bash -c "${command}" 2>> $LOG_FILE | tee -a $LOG_FILE)
    local status=$?
  else
    # 远程执行
    echo "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: INFO: [exec] sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${host}:${SSH_PORT} \"${command}\"" >> $LOG_FILE
    COMMAND_OUTPUT=$(sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${host} -p ${SSH_PORT} "${command}" 2>> $LOG_FILE | tee -a $LOG_FILE)
    local status=$?
  fi
  return $status
}


function command_exists() {
  # 检查命令是否存在
  
  local cmd=${1}
  local package=${2}

  if command -V "$cmd" > /dev/null 2>&1; then
    log::info "[check]" "$cmd command exists."
  else
    log::warning "[check]" "I require $cmd but it's not installed."
    log::warning "[check]" "install $package package."
    yum -y install ${package} >> $LOG_FILE 2>&1
  fi
}


function init_node() {
  # 节点初始化命令
  
  # Disable selinux
  sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config
  setenforce 0
  
  # Disable swap
  swapoff -a && sysctl -w vm.swappiness=0
  sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab

  # Disable firewalld
  systemctl stop firewalld
  systemctl disable firewalld

  # repo
  [ -f /etc/yum.repos.d/CentOS-Base.repo ] && sed -e 's!^#baseurl=!baseurl=!g' \
    -e 's!^mirrorlist=!#mirrorlist=!g' \
    -e 's!mirror.centos.org!mirrors.aliyun.com!g' \
    -i /etc/yum.repos.d/CentOS-Base.repo
  
  yum install -y epel-release
  
  [ -f /etc/yum.repos.d/CentOS-Base.repo ] && sed -e 's!^mirrorlist=!#mirrorlist=!g' \
    -e 's!^metalink=!#metalink=!g' \
    -e 's!^#baseurl=!baseurl=!g' \
    -e 's!//download\.fedoraproject\.org/pub!//mirrors.aliyun.com!g' \
    -e 's!http://mirrors\.aliyun!https://mirrors.aliyun!g' \
    -i /etc/yum.repos.d/epel.repo

  # Change limits
  [ ! -f /etc/security/limits.conf_bak ] && cp /etc/security/limits.conf{,_bak}
  cat << EOF > /etc/security/limits.conf
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
EOF

  [ -f /etc/security/limits.d/20-nproc.conf ] && sed -i 's#4096#655360#g' /etc/security/limits.d/20-nproc.conf
  cat << EOF >> /etc/systemd/system.conf
DefaultLimitCORE=infinity
DefaultLimitNOFILE=655360
DefaultLimitNPROC=655360
EOF

   # Change sysctl
   cat << EOF >  /etc/sysctl.d/99-kube.conf
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
fs.inotify.max_user_instances=1024
fs.inotify.max_user_watches=102400
fs.inotify.max_queued_events=65536

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
net.core.somaxconn = 4096

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
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# 要求iptables不对bridge的数据进行处理
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1

# 持久连接
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10

# 增加conntrack表的大小
net.netfilter.nf_conntrack_max=1024000

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
EOF
  sysctl --system

  # history
  cat << EOF >> /etc/bashrc
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
PS1="\[\033[0m\]\[\033[1;36m\][\u\[\033[0m\]@\[\033[1;32m\]\h\[\033[0m\] \[\033[1;31m\]\w\[\033[0m\]\[\033[1;36m\]]\[\033[33;1m\]# \[\033[0m\]"
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

  # time sync
  yum install -y chrony 
  [ ! -f /etc/chrony.conf_bak ] && cp /etc/chrony.conf{,.bak} #备份默认配置
  cat << EOF > /etc/chrony.conf
server ntp6.aliyun.com iburst
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

  systemctl enable chronyd
  systemctl start chronyd
  chronyc sources -v > /dev/null
  chronyc sourcestats > /dev/null

  # ipvs
  yum install -y ipvsadm ipset sysstat conntrack libseccomp
  module=(
  ip_vs
  ip_vs_rr
  ip_vs_wrr
  ip_vs_sh
  nf_conntrack
  br_netfilter
  )
  for kernel_module in ${module[@]};do
     /sbin/modinfo -F filename $kernel_module |& grep -qv ERROR && echo $kernel_module >> /etc/modules-load.d/ipvs.conf || :
  done
  systemctl enable --now systemd-modules-load.service

}


function upgrade_kernel() {
  # 升级内核

  local ver=$(rpm --eval '%{centos_ver}')

  yum install -y https://www.elrepo.org/elrepo-release-${ver}.el${ver}.elrepo.noarch.rpm
  sed -e 's!^mirrorlist=!#mirrorlist=!g' \
      -e 's!elrepo.org/linux!mirrors.tuna.tsinghua.edu.cn/elrepo!g' \
      -i /etc/yum.repos.d/elrepo.repo
  yum --disablerepo="*" --enablerepo=elrepo-kernel install -y kernel-ml{,-devel}

  grub2-set-default 0 && grub2-mkconfig -o /etc/grub2.cfg
  grubby --default-kernel
  grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
  
}


function init_upgrade_kernel() {
  # 升级节点内核

  [[ "x${UPGRADE_KERNEL_TAG:-}" != "x1" ]] && return

  for host in $MASTER_NODES $WORKER_NODES
  do
    log::info "[init]" "upgrade kernel: $host"
    exec_command "${host}" "$(declare -f upgrade_kernel); upgrade_kernel"
    check_exit_code "$?" "init" "upgrade kernel $host"
  done
  
  for host in $MASTER_NODES $WORKER_NODES
  do
    exec_command "${host}" "bash -c 'sleep 10 && reboot' &>/dev/null &"
    check_exit_code "$?" "init" "$host: Wait for 10s to restart"
  done

  log::info "[notice]" "Please execute the command again!" 
  log::info "[cmd]" "bash $0 ${SCRIPT_PARAMETER%%--upgrade-kernel}"
  log::access "[cmd]" "bash $0 ${SCRIPT_PARAMETER%%--upgrade-kernel}"
  exit 0
}


function init() {
  # 初始化节点
  

  init_upgrade_kernel

  local index=1
  # master节点
  for host in $MASTER_NODES
  do
    log::info "[init]" "master: $host"
    exec_command "${host}" "$(declare -f init_node); init_node"
    check_exit_code "$?" "init" "init master $host"

    # 设置主机名
    exec_command "${host}" "
      echo "$INIT_NODE $KUBE_APISERVER" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-master-node${index}
    "
    check_exit_code "$?" "init" "$host set hostname"

    # 设置主机名解析
    local i=1
    for h in $MASTER_NODES
    do
      exec_command "${host}" "echo '$h ${HOSTNAME_PREFIX}-master-node${i}'  >> /etc/hosts"
      check_exit_code "$?" "init" "$host: add $h hostname resolve"
      i=$((i + 1))
    done
    
    local i=1
    for h in $WORKER_NODES
    do
      exec_command "${host}" "echo '$h ${HOSTNAME_PREFIX}-worker-node${i}'  >> /etc/hosts"
      check_exit_code "$?" "init" "$host: add $h hostname resolve"
      i=$((i + 1))
    done
    
    index=$((index + 1))
  done
   
  # worker 节点
  local index=1
  for host in $WORKER_NODES
  do
    log::info "[init]" "worker: $host"
    exec_command "${host}" "$(declare -f init_node); init_node"
    check_exit_code "$?" "init" "init worker $host"

    # 设置主机名
    exec_command "${host}" "
      echo '127.0.0.1 $KUBE_APISERVER' >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-worker-node${index}
    "

    # 设置主机名解析
    local i=1
    for h in $MASTER_NODES
    do
      exec_command "${host}" "echo '$h ${HOSTNAME_PREFIX}-master-node${i}'  >> /etc/hosts"
      check_exit_code "$?" "init" "$host: add $h hostname resolve"
      i=$((i + 1))
    done
    
    local i=1
    for h in $WORKER_NODES
    do
      exec_command "${host}" "echo '$h ${HOSTNAME_PREFIX}-worker-node${i}'  >> /etc/hosts"
      check_exit_code "$?" "init" "$host: add $h hostname resolve"
      i=$((i + 1))
    done

    index=$((index + 1))
  done


}


function init_add_node() {
  # 初始化添加的节点
  
  init_upgrade_kernel

  local index=0
  exec_command "${INIT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].metadata.name}' | grep -Eo '[0-9]+\$'
  "
  [[ "$?" == "0" ]] && index="${COMMAND_OUTPUT}"
    
  index=$(( index + 1 ))
  
  exec_command "${INIT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {.metadata.name }\\n{end}'
  "
  [[ "$?" == "0" ]] && local node_hosts="${COMMAND_OUTPUT}"
  
  exec_command "${INIT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address } {end}' | awk '{print \$1}'
  "
  [[ "$?" == "0" ]] && INIT_NODE="${COMMAND_OUTPUT}"

  # master节点
  for host in $MASTER_NODES
  do
    if [[ $node_hosts == *"$host"* ]]; then
      log::err "[init]" "The host $host is already in the cluster!"
      exit 1
    fi

    log::info "[init]" "master: $host"
    exec_command "${host}" "$(declare -f init_node); init_node"
    check_exit_code "$?" "init" "init master $host"

    # 设置主机名和解析
    exec_command "${host}" "
      echo "$INIT_NODE $KUBE_APISERVER" >> /etc/hosts
      printf "\"$node_hosts\"" >> /etc/hosts
      echo "${host:-} ${HOSTNAME_PREFIX}-master-node${index}" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-master-node${index}
    "
    check_exit_code "$?" "init" "$host set hostname and resolve"
    index=$((index + 1))
  done
   
  # worker 节点
  index=0
  exec_command "${INIT_NODE}" "
    kubectl get node --selector='!node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].metadata.name}' | grep -Eo '[0-9]+\$'
  "
  [[ "$?" == "0" ]] && index="${COMMAND_OUTPUT}"
  
  index=$(( index + 1 ))
  for host in $WORKER_NODES
  do
    if [[ $node_hosts == *"$host"* ]]; then
      log::err "[init]" "The host $host is already in the cluster!"
      exit 1
    fi
    log::info "[init]" "worker: $host"
    exec_command "${host}" "$(declare -f init_node); init_node"
    check_exit_code "$?" "init" "init worker $host"

    # 设置主机名和解析
    exec_command "${host}" "
      echo '127.0.0.1 $KUBE_APISERVER' >> /etc/hosts
      printf "\"$node_hosts\"" >> /etc/hosts
      echo "${host} ${HOSTNAME_PREFIX}-worker-node${index}" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-worker-node${index}
    "
    check_exit_code "$?" "init" "$host set hostname and resolve"
    index=$((index + 1))
  done
}


function haproxy_backend() {
  # 添加或删除haproxy的后端server

  local action=${1:-add}
  local action_cmd=""
  
  if [[ "$MASTER_NODES" != "" && "$MASTER_NODES" != "127.0.0.1" ]]; then
    exec_command "${INIT_NODE}" "
      kubectl get node --selector='!node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
    "
    [[ "$?" == "0" ]] && local work_nodes="${COMMAND_OUTPUT}"
    
    for host in ${work_nodes:-}
    do
      log::info "[del]" "${host}: ${action} apiserver from haproxy"
      for m in $MASTER_NODES
      do
        if [[ "${action}" == "add" ]]; then
           local num=$(echo "${m}"| awk -F'.' '{print $4}')
           action_cmd="echo \"    server apiserver${num} ${m}:6443 check\" >> /etc/haproxy/haproxy.cfg"
        else
           action_cmd="sed -i -e \"/${m}/d\" /etc/haproxy/haproxy.cfg"
        fi

        exec_command "${host}" "
          ${action_cmd}
          haproxy -c -f /etc/haproxy/haproxy.cfg
          systemctl reload haproxy
        "
        check_exit_code "$?" "del" "${host}: ${action} apiserver(${m}) from haproxy"
      done
    done
  fi
}


function install_docker() {
  # 安装docker
  
  local version="-${1:-latest}"
  version="${version#-latest}"

  cat << EOF > /etc/yum.repos.d/docker-ce.repo
[docker-ce-stable]
name=Docker CE Stable - \$basearch
baseurl=https://mirrors.aliyun.com/docker-ce/linux/centos/$(rpm --eval '%{centos_ver}')/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://mirrors.aliyun.com/docker-ce/linux/centos/gpg
EOF

  yum remove -y docker \
                docker-client \
                docker-client-latest \
                docker-common \
                docker-latest \
                docker-latest-logrotate \
                docker-logrotate \
                docker-engine

  yum install -y docker-ce${version} \
                 docker-ce-cli${version} \
                 containerd.io  \
                 bash-completion
  
  [ ! -f /usr/share/bash-completion/completions/docker ] && \
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
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10,
  "storage-driver": "overlay2",
  "storage-opts": ["overlay2.override_kernel_check=true"],
  "exec-opts": ["native.cgroupdriver=systemd"],
  "registry-mirrors": [
    "https://yssx4sxy.mirror.aliyuncs.com/",
    "https://docker.mirrors.ustc.edu.cn/"
  ]
}
EOF
  systemctl enable docker
  systemctl start docker
}


function install_kube() {
  # 安装kube组件
  
  local version="-${1:-latest}"
  version="${version#-latest}"
  
  cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF

  yum install -y kubeadm${version} \
                 kubelet${version} \
                 kubectl${version} \
                 --disableexcludes=kubernetes

  [ -d /etc/bash_completion.d ] && kubectl completion bash > /etc/bash_completion.d/kubectl
  systemctl enable kubelet
  systemctl start kubelet
}


function install_haproxy() {
   # 安装haproxy
   
   local api_servers="$*"
   
   yum install -y haproxy
   [ ! -f /etc/haproxy/haproxy.cfg_bak ] && cp /etc/haproxy/haproxy.cfg{,_bak}
cat << EOF > /etc/haproxy/haproxy.cfg
global
  log 127.0.0.1 local0
  log 127.0.0.1 local1 notice
  log /dev/log local0 info
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
   bind :6443
   default_backend kube-apiserver-backend

backend kube-apiserver-backend
    mode tcp
    balance roundrobin
    stick-table type ip size 200k expire 30m
    stick on src
$(index=1;for h in $api_servers;do echo "    server apiserver${index} $h:6443 check";index=$((index+1));done)
EOF

  systemctl restart haproxy
  systemctl enable haproxy
}


function install_package() {
  # 安装包
  
  for host in $MASTER_NODES $WORKER_NODES
  do
    # install docker
    log::info "[install]" "install docker on $host."
    exec_command "${host}" "$(declare -f install_docker);install_docker $DOCKER_VERSION"
    check_exit_code "$?" "install" "install docker on $host"

    # install kube
    log::info "[install]" "install kube on $host"
    exec_command "${host}" "$(declare -f install_kube);install_kube $KUBE_VERSION"
    check_exit_code "$?" "install" "install kube on $host"
  done

  local apiservers=$MASTER_NODES
  if [[ "$apiservers" == "127.0.0.1" ]]; then
    exec_command "${INIT_NODE}" "ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'"
    [[ "$?" == "0" ]] && apiservers="${COMMAND_OUTPUT}"
  fi

  if [[ "x${ADD_TAG:-}" == "x1" ]]; then
    exec_command "${INIT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
    "
    [[ "$?" == "0" ]] && apiservers="${COMMAND_OUTPUT}"
  fi
  
  for host in $WORKER_NODES
  do
    # install haproxy
    log::info "[install]" "install haproxy on $host"
    exec_command "${host}" "$(declare -f install_haproxy);install_haproxy "$apiservers""
    check_exit_code "$?" "install" "install haproxy on $host"
  done
}


function check_command() {
  # 检查用到的命令
  
  command_exists ssh openssh
  command_exists sshpass sshpass
  command_exists wget wget
}


function check_ssh_conn() {
  # 检查ssh连通性

  for host in $MASTER_NODES $WORKER_NODES
  do
    [ "$host" == "127.0.0.1" ] && continue
    exec_command "${host}" "exit"
    check_exit_code "$?" "check" "ssh $host connection" "exit"
  done
}


function check_apiserver_conn() {
  # 检查apiserver连通性

  exec_command "${INIT_NODE}" "
     kubectl get node
  "
  check_exit_code "$?" "check" "conn apiserver" "exit"
}


function check_exit_code() {
  # 检查返回码

  local code=${1:-}
  local app=${2:-}
  local desc=${3:-}
  local exit_script=${4:-}

  if [[ "x${code}" == "x0" ]]; then
    log::info "[${app}]" "${desc} succeeded."
  else
    log::err "[${app}]" "${desc} failed."
    [[ "x$exit_script" == "xexit" ]] && exit $code
  fi
}


function check() {
  # 预检
  
  # check command
  check_command

  # check ssh conn
  check_ssh_conn

  # check apiserver conn
  [[ "x${INIT_TAG:-}" != "x1" ]] && check_apiserver_conn  
  
}


function kubeadm_init() {
  # 集群初始化
  
  log::info "[kubeadm init]" "kubeadm init on $INIT_NODE"
  log::info "[kubeadm init]" "$INIT_NODE: set kubeadmcfg.yaml"
  exec_command "${INIT_NODE}" "
    cat << EOF > /tmp/kubeadmcfg.yaml
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs

---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
maxPods: 1000

---
apiVersion: kubeadm.k8s.io/v1beta1
kind: ClusterConfiguration
kubernetesVersion: $KUBE_VERSION
controlPlaneEndpoint: $KUBE_APISERVER:6443
networking:
  dnsDomain: cluster.local
  podSubnet: $KUBE_POD_SUBNET
  serviceSubnet: $KUBE_SERVICE_SUBNET
imageRepository: $KUBE_IMAGE_REPO
apiServer:
  certSANs:
  - 127.0.0.1
  - $KUBE_APISERVER
$(for h in $MASTER_NODES;do echo "  - $h";done)
  extraVolumes:
  - name: localtime
    hostPath: /etc/localtime
    mountPath: /etc/localtime
    readOnly: true
    pathType: File
controllerManager:
  extraArgs:
    bind-address: 0.0.0.0
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
EOF
"
  check_exit_code "$?" "kubeadm init" "$INIT_NODE: set kubeadmcfg.yaml" "exit"
  
  log::info "[kubeadm init]" "$INIT_NODE: kubeadm init start."
  exec_command "${INIT_NODE}" "kubeadm init --config=/tmp/kubeadmcfg.yaml --upload-certs"
  check_exit_code "$?" "kubeadm init" "$INIT_NODE: kubeadm init" "exit"
  
  sleep 3

  log::info "[kubeadm init]" "$INIT_NODE: set kube config."
  exec_command "${INIT_NODE}" '
     mkdir -p $HOME/.kube
     sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
  '
  check_exit_code "$?" "kubeadm init" "$INIT_NODE: set kube config"
  if [[ "$MASTER_NODES" == "127.0.0.1" ]]; then
    log::info "[kubeadm init]" "$INIT_NODE: delete master taint"
    exec_command "127.0.0.1" "kubectl taint nodes --all node-role.kubernetes.io/master-"
    check_exit_code "$?" "kubeadm init" "$INIT_NODE: delete master taint"
  fi
}


function join_cluster() {
  # 加入集群

  log::info "[kubeadm join]" "master: get CACRT_HASH"
  exec_command "${INIT_NODE}" "
    openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //'
  "
  [[ "$?" == "0" ]] && CACRT_HASH="${COMMAND_OUTPUT}"
  
  log::info "[kubeadm join]" "master: get INTI_CERTKEY"
  exec_command "${INIT_NODE}" "
    kubeadm init phase upload-certs --upload-certs 2>> $LOG_FILE | tail -1
  "
  [[ "$?" == "0" ]] && INTI_CERTKEY="${COMMAND_OUTPUT}"
  
  log::info "[kubeadm join]" "master: get INIT_TOKEN"
  exec_command "${INIT_NODE}" "
    kubeadm token create
  "
  [[ "$?" == "0" ]] && INIT_TOKEN="${COMMAND_OUTPUT}"
  
  for host in $MASTER_NODES
  do
    [[ "$INIT_NODE" == "$host" ]] && continue
    log::info "[kubeadm join]" "master $host join cluster."
    exec_command "${host}" "
      kubeadm join $KUBE_APISERVER:6443 --token ${INIT_TOKEN:-} --discovery-token-ca-cert-hash sha256:${CACRT_HASH:-} --control-plane --certificate-key ${INTI_CERTKEY:-}
    "
    check_exit_code "$?" "kubeadm join" "master $host join cluster"

    log::info "[kubeadm join]" "$host: set kube config."
    exec_command "${host}" "
      mkdir -p \$HOME/.kube
      sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config
    "
    check_exit_code "$?" "kubeadm join" "$host: set kube config"
    
    exec_command "${host}" "
      sed -i 's#$INIT_NODE $KUBE_APISERVER#127.0.0.1 $KUBE_APISERVER#g' /etc/hosts
    "
  done

  for host in $WORKER_NODES
  do
    log::info "[kubeadm join]" "worker $host join cluster."
    exec_command "${host}" "
      mkdir -p /etc/kubernetes/manifests
      kubeadm join $KUBE_APISERVER:6443 --token ${INIT_TOKEN:-} --discovery-token-ca-cert-hash sha256:${CACRT_HASH:-}
    "
    check_exit_code "$?" "kubeadm join" "worker $host join cluster"
  
    log::info "[kubeadm join]" "set $host worker node role."
    exec_command "${INIT_NODE}" "
      kubectl get node -o wide | grep "$host" | awk '{print \"kubectl label node \" \$1 \" node-role.kubernetes.io/worker= --overwrite\" }' | bash
    "
    check_exit_code "$?" "kubeadm join" "set $host worker node role"
    
  done
}


function kube_wait() {
  # 等待pod完成

  local app=$1
  local namespace=$2
  local selector=$3

  log::info "[waiting]" "waiting $app"
  exec_command "${INIT_NODE}" "
    kubectl wait --namespace "$namespace" \
    --for=condition=ready pod \
    --selector=$selector \
    --timeout=300s
  "
  check_exit_code "$?" "waiting" "$app pod ready"
}


function kube_apply() {
  # 应用manifest

  local file=$1
  [ -f "$file" ] && local manifest=$(cat $file) || local manifest="${2:-}"

  log::info "[apply]" "$file"
  exec_command "${INIT_NODE}" "
    cat <<EOF | kubectl --validate=false apply -f -
$(printf "%s" "$manifest")
EOF
  "
  check_exit_code "$?" "apply" "add $file"
}


function get_ingress_conn(){
  # 获取ingress连接地址

  exec_command "${INIT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/worker' -o jsonpath='{range.items[*]}{ .status.addresses[?(@.type==\"InternalIP\")].address } {end}' | awk '{print \$1}'
  "
  [[ "$?" == "0" ]] && local node_ip="${COMMAND_OUTPUT}"

  exec_command "${INIT_NODE}" "
    kubectl get svc --all-namespaces -o go-template=\"{{range .items}}{{if eq .metadata.name \\\"ingress-${KUBE_INGRESS}-controller\\\"}}{{range.spec.ports}}{{if eq .port 80}}{{.nodePort}}{{end}}{{end}}{{end}}{{end}}\"
  "
  [[ "$?" == "0" ]] && local node_port="${COMMAND_OUTPUT}"
  
  echo "${node_ip:-nodeIP}:${node_port:-nodePort}"

}


function add_ingress() {
  # 添加ingress组件

  local add_ingress_demo=0

  if [[ "$KUBE_INGRESS" == "nginx" ]]; then
    log::info "[ingress]" "download ingress-nginx manifests"
    wget https://cdn.jsdelivr.net/gh/kubernetes/ingress-nginx@controller-v${INGRESS_NGINX}/deploy/static/provider/baremetal/deploy.yaml -O ${TMP_DIR}/ingress-nginx.yml  >> $LOG_FILE 2>&1
    sed -i "s#k8s.gcr.io#k8sgcr.lework.workers.dev#g" ${TMP_DIR}/ingress-nginx.yml
    sed -i 's#$(POD_NAMESPACE)#\\$(POD_NAMESPACE)#g' ${TMP_DIR}/ingress-nginx.yml
    kube_apply "${TMP_DIR}/ingress-nginx.yml"
    
    kube_wait "ingress-nginx" "ingress-nginx" "app.kubernetes.io/component=controller"
    add_ingress_demo=1

  elif [[ "$KUBE_INGRESS" == "traefik" ]]; then
    log::info "[ingress]" "download ingress-traefik manifests"
    kube_apply "traefik" """
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
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
apiVersion: rbac.authorization.k8s.io/v1beta1
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
            - --log.level=DEBUG
            - --api
            - --api.insecure
            - --entrypoints.web.address=:80
            - --providers.kubernetesingress
          ports:
            - name: web
              containerPort: 80
            - name: admin
              containerPort: 8080

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
      name: web
      targetPort: 80
    - protocol: TCP
      port: 8080
      name: admin
      targetPort: 8080
"""
    kube_wait "traefik" "default" "app=ingress-traefik-controller"
    add_ingress_demo=1

  else
    log::warning "[ingress]" "No $KUBE_INGRESS config."
  fi

  if [[ "x$add_ingress_demo" == "x1" ]]; then
    sleep 3
    log::info "[ingress]" "add ingress app demo"
    kube_apply "ingress-demo-app" """
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
        image: traefik/whoami
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
apiVersion: networking.k8s.io/v1beta1
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
        backend:
          serviceName: ingress-demo-app
          servicePort: 80
"""
     local conn=$(get_ingress_conn)
     log::access "[ingress]" "curl -H 'Host:app.demo.com' ${conn}"
  fi
}


function add_network() {
  # 添加network组件

  if [[ "$KUBE_NETWORK" == "flannel" ]]; then
    log::info "[network]" "download flannel manifests"
    wget https://cdn.jsdelivr.net/gh/coreos/flannel@v${FLANNEL_VERSION}/Documentation/kube-flannel.yml -O ${TMP_DIR}/kube-flannel.yml >> $LOG_FILE 2>&1
    sed -i "s#10.244.0.0/16#$KUBE_POD_SUBNET#g" ${TMP_DIR}/kube-flannel.yml
    
    kube_apply "${TMP_DIR}/kube-flannel.yml"

  elif [[ "$KUBE_NETWORK" == "calico" ]]; then
    log::info "[network]" "download calico manifests"
    exec_command "${INIT_NODE}" "
      wget https://docs.projectcalico.org/manifests/calico.yaml -O /tmp/calico.yml
      wget https://docs.projectcalico.org/manifests/calicoctl.yaml -O /tmp/calicoctl.yaml
      sed -i "s#:v.*#:v${CALICO_VERSION}#g" /tmp/calico.yml
      sed -i "s#:v.*#:v${CALICO_VERSION}#g" /tmp/calicoctl.yaml
      kubectl apply -f /tmp/calico.yml
      kubectl apply -f /tmp/calicoctl.yaml
    "
    check_exit_code "$?" "apply" "add calico"
  else
    log::warning "[network]" "No $KUBE_NETWORK config."
  fi
}


function add_addon() {
  # 添加addon组件

  log::info "[addon]" "download metrics-server manifests"
  wget https://github.com/kubernetes-sigs/metrics-server/releases/download/v${METRICS_SERVER_VERSION}/components.yaml -O ${TMP_DIR}/metrics-server.yml  >> $LOG_FILE 2>&1
  sed -i "s#k8s.gcr.io/metrics-server#$KUBE_IMAGE_REPO#g" ${TMP_DIR}/metrics-server.yml
  sed -i '/--secure-port=4443/a\          - --kubelet-insecure-tls' ${TMP_DIR}/metrics-server.yml
  sed -i '/--secure-port=4443/a\          - --kubelet-preferred-address-types=InternalDNS,InternalIP,ExternalDNS,ExternalIP,Hostname' ${TMP_DIR}/metrics-server.yml
  kube_apply "${TMP_DIR}/metrics-server.yml"
}


function add_monitor() {
  # 添加监控组件
  
  if [[ "$KUBE_MONITOR" == "prometheus" ]]; then
    log::info "[monitor]" "download prometheus manifests"
    exec_command "${INIT_NODE}" "
      wget https://gh.lework.workers.dev/https://github.com/prometheus-operator/kube-prometheus/archive/v${KUBE_PROMETHEUS_VERSION}.zip -O /tmp/prometheus.zip
      command -v unzip 2>/dev/null || yum install -y unzip
      unzip -o /tmp/prometheus.zip -d /tmp/
    "
    check_exit_code "$?" "monitor" "download prometheus"
   
    log::info "[monitor]" "apply prometheus manifests"
    exec_command "${INIT_NODE}" "
      cd /tmp/kube-prometheus-${KUBE_PROMETHEUS_VERSION} \
      && kubectl apply -f manifests/setup/ \
      && until kubectl get servicemonitors --all-namespaces ; do date; sleep 1; echo ''; done \
      && kubectl apply -f manifests/
    "
    check_exit_code "$?" "apply" "add prometheus"

    log::info "[monitor]" "set controller-manager and scheduler prometheus discovery service"
    exec_command "${INIT_NODE}" "
      cat <<EOF | kubectl --validate=false apply -f -
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
EOF
    "
    check_exit_code "$?" "apply" "set controller-manager and scheduler prometheus discovery"

    log::info "[monitor]" "add prometheus ingress"
    exec_command "${INIT_NODE}" "
      cat <<EOF | kubectl --validate=false apply -f -
---
apiVersion: extensions/v1beta1
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
      - backend:
          serviceName: grafana
          servicePort: 3000
---
apiVersion: extensions/v1beta1
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
      - backend:
          serviceName: prometheus-k8s
          servicePort: 9090
---
apiVersion: extensions/v1beta1
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
      - backend:
          serviceName: alertmanager-main
          servicePort: 9093
EOF
    "
    local s="$?"
    check_exit_code "$s" "apply" "add prometheus ingress"
    
    if [[ "$s" == "0" ]]; then
      local conn=$(get_ingress_conn)
      log::access "[ingress]" "curl -H 'Host:grafana.monitoring.cluster.local' ${conn}"
      log::access "[ingress]" "curl -H 'Host:prometheus.monitoring.cluster.local' ${conn}"
      log::access "[ingress]" "curl -H 'Host:alertmanager.monitoring.cluster.local' ${conn}"
    fi
    
  else
    log::warning "[addon]" "No $KUBE_MONITOR config."
  fi
}


function add_log() {
  # 添加log组件

  if [[ "$KUBE_LOG" == "elasticsearch" ]]; then
    log::info "[log]" "add elasticsearch"
    exec_command "${INIT_NODE}" """
      cat <<EOF | kubectl apply -f -
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
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:${ELASTICSEARCH_VERSION}
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
apiVersion: extensions/v1beta1
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
      - backend:
          serviceName: elasticsearch
          servicePort: 9200
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
        image: docker.elastic.co/kibana/kibana:${ELASTICSEARCH_VERSION}
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
apiVersion: extensions/v1beta1
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
      - backend:
          serviceName: kibana
          servicePort: 5601
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
        image: fluent/fluentd-kubernetes-daemonset:v1.11.2-debian-elasticsearch7-1.0
        env:
          - name:  FLUENT_ELASTICSEARCH_HOST
            value: elasticsearch.kube-logging.svc.cluster.local
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
EOF
    """
    local s="$?"
    check_exit_code "$s" "apply" "add elasticsearch"
      
    if [[ "$s" == "0" ]]; then
      local conn=$(get_ingress_conn)
      log::access "[ingress]" "curl -H 'Host:kibana.logging.cluster.local' ${conn}"
      log::access "[ingress]" "curl -H 'Host:elasticsearch.logging.cluster.local' ${conn}"
    fi
  else
    log::warning "[log]" "No $KUBE_LOG config."
  fi

}


function add_storage() {
  # 添加存储 

  if [[ "$KUBE_STORAGE" == "rook" ]]; then

    log::info "[storage]" "add rook"
    log::info "[storage]" "download rook manifests"
    exec_command "${INIT_NODE}" """
      wget https://gh.lework.workers.dev/https://github.com/rook/rook/archive/v${ROOK_VERSION}.zip  -O /tmp/rook-${ROOK_VERSION}.zip
      command -v unzip 2>/dev/null || yum install -y unzip
      unzip -o /tmp/rook-${ROOK_VERSION}.zip -d /tmp/
    """
    check_exit_code "$?" "storage" "download rook manifests"

    log::info "[storage]" "add rook operator"
    exec_command "${INIT_NODE}" """
      cd /tmp/rook-${ROOK_VERSION}/cluster/examples/kubernetes/ceph/ \
      && kubectl apply -f common.yaml -f operator.yaml
    """
    check_exit_code "$?" "apply" "add rook operator"

    log::info "[storage]" "create ceph cluster"
    exec_command "${INIT_NODE}" """
      cd /tmp/rook-${ROOK_VERSION}/cluster/examples/kubernetes/ceph/ \
      && kubectl apply -f cluster.yaml
"""
    check_exit_code "$?" "apply" "add ceph"

  else
    log::warning "[storage]" "No $KUBE_STORAGE config."
  fi
}


function kube_ops() {
   # 运维操作
   
   log::info "[ops]" "add etcd snapshot cronjob"
   kube_apply "etcd-snapshot" """
---
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: etcd-snapshot
  namespace: kube-system
spec:
  # activeDeadlineSeconds: 100
  schedule: '1 */8 * * *'
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: etcd-snapshot
            # Same image as in /etc/kubernetes/manifests/etcd.yaml
            image: ${KUBE_IMAGE_REPO}/etcd:3.4.13-0
            env:
            - name: ETCDCTL_API
              value: '3'
            command: ['/bin/sh']
            args: [\"-c\", \"etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt --key=/etc/kubernetes/pki/etcd/healthcheck-client.key snapshot save /var/lib/etcd/etcd-snapshot-\\\$(date +%Y-%m-%d_%H:%M:%S_%Z).db\"]
            volumeMounts:
            - mountPath: /etc/kubernetes/pki/etcd
              name: etcd-certs
              readOnly: true
            - mountPath: /var/lib/etcd
              name: etcd-data
          restartPolicy: OnFailure
          nodeSelector:
            node-role.kubernetes.io/master: ''
          tolerations:
          - effect: NoSchedule
            operator: Exists
          hostNetwork: true
          volumes:
          - name: etcd-certs
            hostPath:
              path: /etc/kubernetes/pki/etcd
              type: DirectoryOrCreate
          - name: etcd-data
            hostPath:
              path: /var/lib/etcd
              type: DirectoryOrCreate
"""
}


function kube_status() {
  # 集群状态
  
  sleep 5
  log::info "[cluster]" "cluster status"
  exec_command "${INIT_NODE}" "
     echo
     kubectl get node -o wide
     echo
     kubectl get pods -A
  "
  [[ "$?" == "0" ]] && printf "${COMMAND_OUTPUT}"
}


function reset_node() {
  # 重置节点

  local host=$1
  log::info "[reset]" "node $host"
  exec_command "${host}" "
    kubeadm reset -f || echo 0
    systemctl stop kubelet
    [ -f /etc/haproxy/haproxy.cfg ] && systemctl stop haproxy
    sed -i -e \"/$KUBE_APISERVER/d\" -e '/-worker-/d' -e '/-master-/d' /etc/hosts
    iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
    [ -d /var/lib/kubelet ] && find /var/lib/kubelet | xargs -n 1 findmnt -n -t tmpfs -o TARGET -T | uniq | xargs -r umount -v
    rm -rf /etc/kubernetes/* /var/lib/etcd/* \$HOME/.kube /etc/cni/net.d/* /var/lib/elasticsearch/*
    docker rm -f -v \$(docker ps | grep kube | awk '{print \$1}') || echo 0
    systemctl restart docker
    ipvsadm --clear || echo 0
    ip link delete flannel.1 || echo 0
    ip link delete cni0 || echo 0
    ip link delete tunl0 || echo 0
  "
  check_exit_code "$?" "reset" "$host: reset"
}


function reset_all() {
  # 重置所有节点
  
  local all_node=""
  
  exec_command "${INIT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {end}'
  "
  [[ "$?" == "0" ]] && all_node="${COMMAND_OUTPUT}"

  for host in $all_node
  do
    reset_node "$host"
  done

}


function start_init() {
  # 初始化集群

  INIT_NODE=$(echo ${MASTER_NODES} | awk '{print $1}')

  # 1. 初始化集群
  init
  # 2. 安装包
  install_package
  # 3. 加载提供的文件
  # 4. 初始化kubeadm
  kubeadm_init
  # 5. 加入集群
  join_cluster
  # 6. 添加network
  add_network
  # 7. 安装addon
  add_addon
  # 8. 添加ingress
  add_ingress
  # 9. 添加monitor
  [[ "x${MONITOR_TAG:-}" == "x1" ]] && add_monitor
  # 10. 运维操作
  kube_ops
  # 11. 查看集群状态
  kube_status
}


function add_node() {
  # 添加节点
  
  # 1. 初始化节点
  init_add_node
  # 2. 安装包
  install_package
  # 3. 加入集群
  join_cluster
  # 4. haproxy添加apiserver
  haproxy_backend "add"
  # 5. 查看集群状态
  kube_status
}


function del_node() {
  # 删除节点
 
  haproxy_backend "remove"

  for host in $MASTER_NODES $WORKER_NODES
  do
    log::info "[del]" "node $host"

    exec_command "${INIT_NODE}" "
      kubectl get node -o wide | grep $host | awk '{print \$1}'
    "
    [[ "$?" == "0" ]] && local node_name="${COMMAND_OUTPUT}"
    if [[ "${node_name:-}" == "" ]]; then
      log::err "[del]" "node $host not found."
      continue
    fi

    log::info "[del]" "drain $host"
    exec_command "${INIT_NODE}" "kubectl drain $node_name --force --ignore-daemonsets --delete-local-data"
    check_exit_code "$?" "del" "$host: drain"

    log::info "[del]" "delete node $host"
    exec_command "${INIT_NODE}" "kubectl delete node $node_name"
    check_exit_code "$?" "del" "$host: delete"

    sleep 3
    reset_node "$host"
  done

  kube_status
}


function upgrage_node() {
  # 节点软件升级

  local role=${1:-init}
  local version="-${2:-latest}"
  version="${version#-latest}"

  echo '[install] kubeadm'
  kubeadm version
  yum install -y kubeadm${version} --disableexcludes=kubernetes
  kubeadm version

  echo '[upgrade]'
  if [[ "$role" == "init" ]]; then
    local plan_info=$(kubeadm upgrade plan)
    local v=$(printf "$plan_info" | grep 'kubeadm upgrade apply ' | awk '{print $4}')
    printf "${plan_info}\n"
    kubeadm upgrade apply ${v} -y
  else
    kubeadm upgrade node
  fi

  echo '[install] kubelet kubectl'
  kubectl version --client=true
  yum install -y kubelet${version} kubectl${version} --disableexcludes=kubernetes
  kubectl version --client=true
  systemctl daemon-reload
  systemctl restart kubelet
}


function upgrade() {
  # 升级

  log::info "[upgrade]" "upgrade to $KUBE_VERSION"

  if [[ "${KUBE_VERSION}" != "latest" ]]; then
    local local_version=""
    exec_command "${INIT_NODE}" "kubeadm version -o short"
    [[ "$?" == "0" ]] && local_version="${COMMAND_OUTPUT#v}"
    if [[ "${KUBE_VERSION}" == "${local_version}" ]];then
      log::warning "[check]" "The specified version(${KUBE_VERSION}) is consistent with the local version(${local_version})!"
      exit 1
    fi

    if [[ $(version $KUBE_VERSION) < $(version ${local_version}) ]];then
      log::warning "[check]" "The specified version($KUBE_VERSION) is less than the local version(${local_version})!"
      exit 1
    fi

    local stable_version=""
    exec_command "${INIT_NODE}" "wget https://storage.googleapis.com/kubernetes-release/release/stable.txt -q -O -"
    [[ "$?" == "0" ]] && stable_version="${COMMAND_OUTPUT#v}"
    if [[ $(version $KUBE_VERSION) > $(version ${stable_version}) ]];then
      log::warning "[check]" "The specified version($KUBE_VERSION) is more than the stable version(${stable_version})!"
      exit 1
    fi
  fi

  local node_hosts=""
  exec_command "${INIT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.metadata.name } {end}'
  "
  [[ "$?" == "0" ]] && local node_hosts="${COMMAND_OUTPUT}"

  local plan=0
  for host in ${node_hosts}
  do
    log::info "[upgrade]" "node: $host"
    exec_command "${INIT_NODE}" "kubectl drain ${host} --ignore-daemonsets --delete-local-data"
    check_exit_code "$?" "upgrade" "drain ${host} node" "exit"
    sleep 5

    if [[ ${plan} == "0" ]]; then
      exec_command "${host}" "$(declare -f upgrage_node); upgrage_node 'init' '$KUBE_VERSION'"
      check_exit_code "$?" "upgrade" "plan and upgrade cluster on ${host}"
      plan=1
    else
      exec_command "${host}" "$(declare -f upgrage_node); upgrage_node 'node' '$KUBE_VERSION'"
      check_exit_code "$?" "upgrade" "upgrade ${host} node"
    fi

    exec_command "${INIT_NODE}" "kubectl wait --for=condition=Ready node/${host} --timeout=120s"
    check_exit_code "$?" "upgrade" "${host} ready"
    sleep 5
    exec_command "${INIT_NODE}" "kubectl uncordon ${host}"
    check_exit_code "$?" "upgrade" "uncordon ${host} node"
    sleep 5
  done
  
  kube_status
}


function usage {
  # 使用帮助
  
  cat << EOF

Install kubernetes cluster using kubeadm.

Usage:
  $(basename $0) [command]

Available Commands:
  init            init Kubernetes cluster.
  reset           reset Kubernetes cluster.
  add             add nodes to the cluster.
  del             remove node from the cluster.
  upgrade         Upgrading kubeadm clusters.

Flag:
  -m,--master          master node, default: ''
  -w,--worker          work node, default: ''
  -u,--user            ssh user, default: ${SSH_USER}
  -p,--password        ssh password,default: ${SSH_PASSWORD}
  -P,--port            ssh port, default: ${SSH_PORT}
  -v,--version         kube version, default: ${KUBE_VERSION}
  -n,--network         cluster network, choose: [flannel,calico], default: ${KUBE_NETWORK}
  -i,--ingress         ingress controller, choose: [nginx,traefik], default: ${KUBE_INGRESS}
  -M,--monitor         cluster monitor, choose: [prometheus]
  -l,--log             cluster log, choose: [elasticsearch]
  -s,--storage         cluster storage, choose: [rook]
  -U,--upgrade-kernel  upgrade kernel

Example:
  [cluster node]
  $0 init \\
  --master 192.168.77.130,192.168.77.131,192.168.77.132 \\
  --worker 192.168.77.133,192.168.77.134,192.168.77.135 \\
  --user root \\
  --password 123456 \\
  --version 1.19.2

  [cluster node]
  $0 reset \\
  --user root \\
  --password 123456

  [add node]
  $0 add \\
  --master 192.168.77.140,192.168.77.141 \\
  --worker 192.168.77.143,192.168.77.144 \\
  --user root \\
  --password 123456 \\
  --version 1.19.2

  [del node]
  $0 del \\
  --master 192.168.77.140,192.168.77.141 \\
  --worker 192.168.77.143,192.168.77.144 \\
  --user root \\
  --password 123456
 
  [other]
  $0 upgrade --version 1.19.2
  $0 add --ingress traefik
  $0 add --monitor prometheus
  $0 add --log elasticsearch
  $0 add --storage rook

EOF
  exit 1
}


######################################################################################################
# main
######################################################################################################


[ "$#" == "0" ] && usage

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
    upgrade )               UPGRADE_TAG=1
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
    -U | --upgrade-kernel ) shift
                            UPGRADE_KERNEL_TAG=1
                            ;;
    * )                     usage
                            exit 1
  esac
  shift
done

# 开始
log::info "[start]" "bash $0 ${SCRIPT_PARAMETER}"

# 转换
MASTER_NODES=$(echo ${MASTER_NODES} | tr ',' ' ')
WORKER_NODES=$(echo ${WORKER_NODES} | tr ',' ' ')

# 预检
check

# 启动
if [[ "x${RESET_TAG:-}" == "x1" ]]; then
  reset_all
elif [[ "x${INIT_TAG:-}" == "x1" ]]; then
  [[ "$MASTER_NODES" == "" ]] && MASTER_NODES="127.0.0.1"
  start_init
elif [[ "x${ADD_TAG:-}" == "x1" ]]; then
  [[ "x${NETWORK_TAG:-}" == "x1" ]] && { add_network; add=1; }
  [[ "x${INGRESS_TAG:-}" == "x1" ]] && { add_ingress; add=1; }
  [[ "x${MONITOR_TAG:-}" == "x1" ]] && { add_monitor; add=1; }
  [[ "x${LOG_TAG:-}" == "x1" ]] && { add_log; add=1; }
  [[ "x${STORAGE_TAG:-}" == "x1" ]] && { add_storage; add=1; }
  [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]] && { add_node; add=1; }
  [[ "${add:-}" != "1" ]] && usage
elif [[ "x${DEL_TAG:-}" == "x1" ]]; then
  [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]] && del_node || usage
elif [[ "x${UPGRADE_TAG:-}" == "x1" ]]; then
  upgrade
else
  usage
fi
