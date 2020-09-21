#!/bin/env bash
###################################################################
#Script Name	: kainstall.sh
#Description	: Install kubernetes cluster using kubeadm.
#Update Date    : 2020-09-18
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
DOCKER_VERSION="19.03.12"
KUBE_VERSION="1.19.2"

# kubeadm
KUBE_APISERVER="apiserver.cluster.local"
KUBE_POD_SUBNET="10.244.0.0/16"
KUBE_SERVICE_SUBNET="10.96.0.0/16"
KUBE_IMAGE_REPO="registry.aliyuncs.com/k8sxio"

# 定义的master和worker节点地址，以逗号分隔
MASTER_NODES="127.0.0.1"
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


trap 'echo -e "\n\n  See detailed log >>> $LOG_FILE \n\n";exit' 1 2 3 15 EXIT

######################################################################################################
# function
######################################################################################################

log::err() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[31mERROR: \033[0m$*\n" | tee -a $LOG_FILE
}

log::info() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[32mINFO: \033[0m$*\n" | tee -a $LOG_FILE
}

log::warning() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: \033[33mWARNING: \033[0m$*\n" | tee -a $LOG_FILE
}

function ssh_exec() {
   # 通过ssh方式执行命令

   local host=$1
   shift
   local command="$@"
   # 命令执行
   echo "[$(date +'%Y-%m-%dT%H:%M:%S.%N%z')]: INFO: [exec] sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${host}:${SSH_PORT} \"${command}\"" >> $LOG_FILE
   sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${host} -p ${SSH_PORT} "${command}" >> $LOG_FILE 2>&1
   local status=$?
   return $status
}


function init_node() {
  # 节点初始化命令
  
  # Disable selinux
  sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config
  setenforce 0
  
  # Disable swap
  swapoff -a && sysctl -w vm.swappiness=0
  sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab
 
  systemctl stop NetworkManager
  systemctl disable NetworkManager

  systemctl stop firewalld
  systemctl disable firewalld

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

  [ ! -f /etc/security/limits.d/20-nproc.conf] && sed -i 's#4096#655360#g' /etc/security/limits.d/20-nproc.conf
  cat << EOF >> /etc/security//etc/systemd/system.conf
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
RateLimitBurst= 1000
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
  yum install chrony -y > /dev/null
  cp /etc/chrony.conf{,.bak} #备份默认配置
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


function init() {
  # 初始化节点
  
  local index=1
  # master节点
  for host in $MASTER_NODES
  do
    log::info "[init]" "master: $host"
    ssh_exec "${host}" "$(declare -f init_node); init_node"
    if [ $? -ne 0 ]; then
      log::err "[init]" "init master $host error."
    else 
      log::info "[init]" "init master $host succeeded."
    fi

    # 设置主机名
    ssh_exec "${host}" "
      echo "$INIT_NODE $KUBE_APISERVER" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-master-node${index}
    "
    if [ $? -ne 0 ]; then
      log::err "[init]" "$host set hostname error."
    else 
      log::info "[init]" "$host set hostname succeeded."
    fi

    # 设置主机名解析
    local i=1
    for h in $MASTER_NODES
    do
      ssh_exec "${host}" "echo '$h ${HOSTNAME_PREFIX}-master-node${i}'  >> /etc/hosts"
      if [ $? -ne 0 ]; then
        log::err "[init]" "$host add $h hostname resolve error."
      else 
        log::info "[init]" "$host add $h hostname resolve succeeded."
      fi
      i=$((i + 1))
    done
    
    local i=1
    for h in $WORKER_NODES
    do
      ssh_exec "${host}" "echo '$h ${HOSTNAME_PREFIX}-worker-node${i}'  >> /etc/hosts"
      if [ $? -ne 0 ]; then
        log::err "[init]" "$host add $h hostname resolve error."
      else 
        log::info "[init]" "$host add $h hostname resolve succeeded."
      fi
      i=$((i + 1))
    done
    
    index=$((index + 1))
  done
   
  # woker 节点
  local index=1
  for host in $WORKER_NODES
  do
    log::info "[init]" "woker: $host"
    ssh_exec "${host}" "$(declare -f init_node); init_node"
    if [ $? -ne 0 ]; then
      log::err "[init]" "init woker $host error."
    else 
      log::info "[init]" "init woker $host succeeded."
    fi

    # 设置主机名
    ssh_exec "${host}" "
      echo '127.0.0.1 $KUBE_APISERVER' >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-worker-node${index}
    "

    # 设置主机名解析
    local i=1
    for h in $MASTER_NODES
    do
      ssh_exec "${host}" "echo '$h ${HOSTNAME_PREFIX}-master-node${i}'  >> /etc/hosts"
      if [ $? -ne 0 ]; then
        log::err "[init]" "$host add $h hostname resolve error."
      else 
        log::info "[init]" "$host add $h hostname resolve succeeded."
      fi
      i=$((i + 1))
    done
    
    local i=1
    for h in $WORKER_NODES
    do
      ssh_exec "${host}" "echo '$h ${HOSTNAME_PREFIX}-worker-node${i}'  >> /etc/hosts"
      if [ $? -ne 0 ]; then
        log::err "[init]" "$host add $h hostname resolve error."
      else 
        log::info "[init]" "$host add $h hostname resolve succeeded."
      fi
      i=$((i + 1))
    done

    index=$((index + 1))
  done
  
}


function init_add_node() {
  # 初始化添加的节点
  
  local index=$(kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{ $.items[*].metadata.name }' | grep -Eo '[0-9]+$')
  index=$(( index + 1 ))
  
  local node_hosts=$(kubectl get node -o jsonpath='{range.items[*]}{ .status.addresses[?(@.type=="InternalIP")].address } {.metadata.name }\n{end}')
  
  INIT_NODE=$(kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{ .status.addresses[?(@.type=="InternalIP")].address } {end}' | awk '{print $1}')

  # master节点
  for host in $MASTER_NODES
  do
    log::info "[init]" "master: $host"
    ssh_exec "${host}" "$(declare -f init_node); init_node"
    if [ $? -ne 0 ]; then
      log::err "[init]" "init master $host error."
    else 
      log::info "[init]" "init master $host succeeded."
    fi

    # 设置主机名和解析
    ssh_exec "${host}" "
      echo "$INIT_NODE $KUBE_APISERVER" >> /etc/hosts
      printf "\"$node_hosts\"" >> /etc/hosts
      echo "${host} ${HOSTNAME_PREFIX}-master-node${index}" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-master-node${index}
    "
    if [ $? -ne 0 ]; then
      log::err "[init]" "$host set hostname error."
    else 
      log::info "[init]" "$host set hostname succeeded."
    fi
    index=$((index + 1))
  done
   
  # woker 节点
  local index=$(kubectl get node --selector='!node-role.kubernetes.io/master' -o jsonpath='{ $.items[*].metadata.name }' | grep -Eo '[0-9]+$')
  index=$(( index + 1 ))
  for host in $WORKER_NODES
  do
    log::info "[init]" "woker: $host"
    ssh_exec "${host}" "$(declare -f init_node); init_node"
    if [ $? -ne 0 ]; then
      log::err "[init]" "init woker $host error."
    else 
      log::info "[init]" "init woker $host succeeded."
    fi

    # 设置主机名和解析
    ssh_exec "${host}" "
      echo '127.0.0.1 $KUBE_APISERVER' >> /etc/hosts
      printf "\"$node_hosts\"" >> /etc/hosts
      echo "${host} ${HOSTNAME_PREFIX}-worker-node${index}" >> /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-worker-node${index}
    "
    index=$((index + 1))
  done
  
}


function install_docker() {
  # 安装docker
  
  local version="-${1:-19.03.12}"

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
  
  cp /usr/share/bash-completion/completions/docker /etc/bash_completion.d/
  
  [ ! -d /etc/docker ] && mkdir /etc/docker
  cat << EOF > /etc/docker/daemon.json
{
  "data-root": "/var/lib/docker",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
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
  
  local version="-${1:-1.19.2}"
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
    ssh_exec "${host}" "$(declare -f install_docker);install_docker $DOCKER_VERSION"
    if [ $? -ne 0 ]; then
      log::err "[install]" "install docker on $host error."
    else 
      log::info "[install]" "install docker on $host succeeded."
    fi

    # install kube
    log::info "[install]" "install kube on $host"
    ssh_exec "${host}" "$(declare -f install_kube);install_kube $KUBE_VERSION"
    if [ $? -ne 0 ]; then
      log::err "[install]" "install kube on $host error."
    else 
      log::info "[install]" "install kube on $host succeeded."
    fi
    
  done

  local apiservers=$MASTER_NODES
  if [[ "x${ADD_TAG:-}" == "x1" ]]; then
    apiservers=$(kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{ $.items[*].status.addresses[?(@.type=="InternalIP")].address }')
  fi
  
  for host in $WORKER_NODES
  do
     # install haproxy
     log::info "[install]" "install haproxy on $host"
     ssh_exec "${host}" "$(declare -f install_haproxy);install_haproxy "$apiservers""
     if [ $? -ne 0 ]; then
       log::err "[install]" "install haproxy on $host error."
     else 
       log::info "[install]" "install haproxy on $host succeeded."
     fi
  done
}


function command_exists() {
  # 检查命令是否存在
  
  if command -V "$1" > /dev/null 2>&1; then
      log::info "[check]" "$1 command exists."
  else
      log::warning "[check]" "I require $1 but it's not installed."
      yum -y install $2 > $LOG_FILE 2>&1
      log::warning "[check]" "install $2 package."
  fi
}


function check_command() {
  # 检查用到的命令
  
  command_exists ssh openssh
  command_exists sshpass sshpass
  command_exists wget wget
}


function check_ssh_conn() {
  # 检查ssh连通性
  
  local conn_status=0
  for host in $MASTER_NODES $WORKER_NODES
  do
    ssh_exec "${host}" "exit"
    if [ $? != "0" ]; then
      log::err "[check]" "ssh $host connection failed."
      conn_status=1
    else
      log::info "[check]" "ssh $host connection succeeded."
    fi
  done

  if [ $conn_status != "0" ]; then
    log::err "[check]" "Please keep the ssh connection open!"
    exit $conn_status
  fi
}


function check() {
  # 预检
  
  # check command
  check_command
  # check ssh conn
  check_ssh_conn
}


function kubeadm_init() {
  # 集群初始化
  
  log::info "[kubeadm init]" "kubeadm init on $INIT_NODE"
  log::info "[kubeadm init]" "$INIT_NODE: set kubeadmcfg.yaml"
  ssh_exec "${INIT_NODE}" "
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
  podSubnet: $KUBE_POD_SUBNET
  serviceSubnet: $KUBE_SERVICE_SUBNET
imageRepository: $KUBE_IMAGE_REPO
apiServer:
  certSANs:
  - $KUBE_APISERVER
$(for h in $MASTER_NODES;do echo "  - $h";done)
  extraVolumes:
  - name: localtime
    hostPath: /etc/localtime
    mountPath: /etc/localtime
    readOnly: true
    pathType: File
controllerManager:
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
    pathType: File
scheduler:
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
    pathType: File
EOF
"   
  if [ $? -ne 0 ]; then
    log::err "[kubeadm init]" "$INIT_NODE: set kubeadmcfg.yaml error."
    exit 1
  else 
    log::info "[kubeadm init]" "$INIT_NODE: set kubeadmcfg.yaml succeeded."
  fi
  
  log::info "[kubeadm init]" "$INIT_NODE: kubeadm init start."
  ssh_exec "${INIT_NODE}" "kubeadm init --config=/tmp/kubeadmcfg.yaml --upload-certs"
  if [ $? -ne 0 ]; then
    log::err "[kubeadm init]" "$INIT_NODE: kubeadm init error."
    exit 1
  else 
    log::info "[kubeadm init]" "$INIT_NODE: kubeadm init succeeded."
  fi
  sleep 3

  log::info "[kubeadm init]" "$INIT_NODE: set kube config."
  ssh_exec "${INIT_NODE}" '
     mkdir -p $HOME/.kube
     sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
   '
}


function join_cluster() {
  # 加入集群

  if [[ "x${ADD_TAG:-}" == "x1" ]]; then
    log::info "[kubeadm join]" "master: get CACRT_HASH"
    CACRT_HASH=$(openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //' 2>> $LOG_FILE)

    log::info "[kubeadm join]" "master: get INTI_CERTKEY"
    INTI_CERTKEY=$(kubeadm init phase upload-certs --upload-certs 2>> $LOG_FILE | tail -1 2>> $LOG_FILE)
  
    log::info "[kubeadm join]" "master: get INIT_TOKEN"
    INIT_TOKEN=$(kubeadm token create 2>>$LOG_FILE)
  else
    log::info "[kubeadm join]" "$host: get CACRT_HASH"
    CACRT_HASH=$(sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${INIT_NODE} -p ${SSH_PORT} "openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //'" 2>> $LOG_FILE)

    log::info "[kubeadm join]" "$host: get INTI_CERTKEY"
    INTI_CERTKEY=$(sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${INIT_NODE} -p ${SSH_PORT} "kubeadm init phase upload-certs --upload-certs | tail -1" 2>> $LOG_FILE)
    
    log::info "[kubeadm join]" "$host: get INIT_TOKEN"
    INIT_TOKEN=$(sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${INIT_NODE} -p ${SSH_PORT} "kubeadm token list | grep bootstrappers | awk '{print \$1}'" 2>> $LOG_FILE)
  fi
  
  for host in $MASTER_NODES
  do
    [[ "$INIT_NODE" == "$host" ]] && continue
    log::info "[kubeadm join]" "master $host join cluster."
    ssh_exec "${host}" "
      kubeadm join $KUBE_APISERVER:6443 --token $INIT_TOKEN --discovery-token-ca-cert-hash sha256:$CACRT_HASH --control-plane --certificate-key $INTI_CERTKEY
    "
    if [ $? -ne 0 ]; then
      log::err "[kubeadm join]" "master $host join cluster error."
      exit 1
    else 
      log::info "[kubeadm join]" "master $host join cluster succeeded."
    fi

    log::info "[kubeadm init]" "$host: set kube config."
    ssh_exec "${INIT_NODE}" '
      mkdir -p $HOME/.kube
      sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
    '
    ssh_exec "${host}" "
      sed -i 's#$INIT_NODE $KUBE_APISERVER#127.0.0.1 $KUBE_APISERVER#g' /etc/hosts
    "
  done

  for host in $WORKER_NODES
  do
    log::info "[kubeadm join]" "worker $host join cluster."
    ssh_exec "${host}" "
      kubeadm join $KUBE_APISERVER:6443 --token $INIT_TOKEN --discovery-token-ca-cert-hash sha256:$CACRT_HASH
    "
    if [ $? -ne 0 ]; then
      log::err "[kubeadm join]" "worker $host join cluster error."
      exit 1
    else 
      log::info "[kubeadm join]" "worker $host join cluster succeeded."
    fi
  
    log::info "[kubeadm join]" "set $host worker node role."
    if [[ "x${ADD_TAG:-}" == "x1" ]]; then
      kubectl get node -o wide | grep "$host" | awk '{print "kubectl label node "$1" node-role.kubernetes.io/worker= --overwrite" }' | bash >> $LOG_FILE 2>&1
    else
      ssh_exec "${INIT_NODE}" "
        kubectl get node -o wide | grep "$host" | awk '{print \"kubectl label node \" \$1 \" node-role.kubernetes.io/worker= --overwrite\" }' | bash
      "
    fi
  done
}


function kube_addon() {
   # 添加addon组件

   log::info "[addon]" "add flannel"
   wget https://cdn.jsdelivr.net/gh/coreos/flannel@v0.12.0/Documentation/kube-flannel.yml -O ${TMP_DIR}/kube-flannel.yml >> $LOG_FILE 2>&1
   sed -i "s#10.244.0.0/16#$KUBE_POD_SUBNET#g" ${TMP_DIR}/kube-flannel.yml
   local manifest=$(cat ${TMP_DIR}/kube-flannel.yml)
   ssh_exec "${INIT_NODE}" "
     cat <<EOF | kubectl --validate=false apply -f -
$(printf "\"$manifest"\")
EOF
   "
   if [ $? -ne 0 ]; then
     log::err "[addon]" "apply flannel error."
   else 
     log::info "[addon]" "apply flannel succeeded."
   fi

   log::info "[addon]" "add metrics-server"
   wget https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.3.7/components.yaml -O ${TMP_DIR}/metrics-server.yml  >> $LOG_FILE 2>&1
   sed -i "s#k8s.gcr.io/metrics-server#$KUBE_IMAGE_REPO#g" ${TMP_DIR}/metrics-server.yml
   sed -i '/--secure-port=4443/a\          - --kubelet-insecure-tls' ${TMP_DIR}/metrics-server.yml
   sed -i '/--secure-port=4443/a\          - --kubelet-preferred-address-types=InternalDNS,InternalIP,ExternalDNS,ExternalIP,Hostname' ${TMP_DIR}/metrics-server.yml
   local manifest=$(cat ${TMP_DIR}/metrics-server.yml)
   ssh_exec "${INIT_NODE}" "
     cat <<EOF | kubectl --validate=false apply -f -
$(printf "\"$manifest\"")
EOF
   "
   if [ $? -ne 0 ]; then
     log::err "[addon]" "apply metrics-server error."
   else 
     log::info "[addon]" "apply metrics-server succeeded."
   fi
}


function kube_status() {
  # 集群状态
  
  sleep 5
  log::info "[cluster]" "cluster status"
  sshpass -p ${SSH_PASSWORD} ssh ${SSH_OPTIONS} ${SSH_USER}@${INIT_NODE} -p ${SSH_PORT} "
     kubectl get node
     kubectl -n kube-system get pods
  " | tee -a $LOG_FILE

}


function reset_node() {
  # 重置命令
  
  kubeadm reset -f || echo 0
  systemctl stop kubelet
  [ -f /etc/haproxy/haproxy.cfg ] && systemctl stop haproxy
  sed -i -e "/$KUBE_APISERVER/d" -e '/-worker-/d' -e '/-master-/d' /etc/hosts
  iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
  [ -d /var/lib/kubelet ] && find /var/lib/kubelet | xargs -n 1 findmnt -n -t tmpfs -o TARGET -T | uniq | xargs -r umount -v
  rm -rf /etc/kubernetes/* /var/lib/etcd/* $HOME/.kube /etc/cni/net.d/*
  docker rm -f -v $(docker ps | grep kube | awk '{print $1}') || echo 0
  systemctl restart docker
  ipvsadm --clear || echo 0
  ip link delete flannel.1 || echo 0
  ip link delete cni0 || echo 0
}


function reset_all() {
  # 重置集群
  
  for host in $MASTER_NODES $WORKER_NODES
  do
     log::info "[reset]" "node $host"
     ssh_exec "${host}" "$(declare -f reset_node);reset_node"
     if [ $? -ne 0 ]; then
       log::err "[reset]" "$host: reset error."
     else 
       log::info "[reset]" "$host: reset succeeded."
     fi
  done

}


function start_init() {
  # 初始化集群
  
  INIT_NODE=$(echo $MASTER_NODES | awk '{print $1}')

  # 1. 预检测
#  check
  # 2. 初始化集群
#  init
  # 3. 安装包
#  install_package
  # 4. 加载提供的文件
  # 5. 初始化kubeadm
#  kubeadm_init
  # 6. 加入集群
#  join_cluster
  # 7. 安装addon
  kube_addon
  # 8. 查看集群状态
#  kube_status
}


function add_node() {
  # 添加节点
  
  # 1. 预检测
  check
  # 2. 初始化集群
  init_add_node
  # 3. 安装包
  install_package
  # 4. 加入集群
  join_cluster
  # 5. 查看集群状态
  kube_status
}


function del_node() {
  # 删除节点
 
  for host in $MASTER_NODES $WORKER_NODES
  do
    log::info "[del]" "node $host"
    local node_name=$(kubectl get node -o wide | grep $host | awk '{print $1}')

    log::info "[del]" "drain $host"
    kubectl drain $node_name --force --ignore-daemonsets --delete-local-data >> $LOG_FILE 2>&1
    if [ $? -ne 0 ]; then
      log::err "[del]" "$host: drain error."
    else 
      log::info "[del]" "$host: drain succeeded."
    fi

    log::info "[del]" "delete node $host"
    kubectl delete node $node_name >> $LOG_FILE 2>&1
    if [ $? -ne 0 ]; then
      log::err "[del]" "$host: delete error."
    else 
      log::info "[del]" "$host: delete succeeded."
    fi
  done

  reset_all

  kube_status
}


function usage {
  # 使用帮助
  echo "Install kubernetes cluster using kubeadm."
  echo
  echo "Usage: $0 init|reset|add|del [-m master] [-w worker] [-u user] [-p password] [-P port] [-v version]"
  echo "  -m,--master     master node, default: ${MASTER_NODES}"
  echo "  -w,--worker     work node, default: ''"
  echo "  -u,--user       ssh user, default: ${SSH_USER}"
  echo "  -p,--password   ssh password,default: ${SSH_PASSWORD}"
  echo "  -P,--port       ssh port, default: ${SSH_PORT}"
  echo "  -v,--version    kube version , default: ${KUBE_VERSION}"
  echo
  echo
  echo "Example:"
  echo "  [init node]"
  echo "  $0 init \\"
  echo "  --master 192.168.77.130,192.168.77.131,192.168.77.132 \\"
  echo "  --worker 192.168.77.133,192.168.77.134,192.168.77.135 \\"
  echo "  --user root \\"
  echo "  --password 123456 \\"
  echo "  --version 1.19.2 \\"
  echo
  echo "  [reset node]"
  echo "  $0 reset \\"
  echo "  --master 192.168.77.130,192.168.77.131,192.168.77.132 \\"
  echo "  --worker 192.168.77.133,192.168.77.134,192.168.77.135 \\"
  echo "  --user root \\"
  echo "  --password 123456 \\"
  echo "  --version 1.19.2 \\"
  echo
  echo "  [add node]"
  echo "  $0 add \\"
  echo "  --master 192.168.77.140,192.168.77.141 \\"
  echo "  --worker 192.168.77.143,192.168.77.144 \\"
  echo "  --user root \\"
  echo "  --password 123456 \\"
  echo "  --version 1.19.2 \\"
  echo
  echo "  [del node]"
  echo "  $0 del \\"
  echo "  --master 192.168.77.140,192.168.77.141 \\"
  echo "  --worker 192.168.77.143,192.168.77.144 \\"
  echo "  --user root \\"
  echo "  --password 123456 \\"
  echo "  --version 1.19.2 \\"
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
    -m | --master )         shift
                            unset MASTER_NODES
                            MASTER_NODES=$(echo $1 | tr ',' ' ')
                            ;;
    -w | --worker )         shift
                            unset WORKER_NODES
                            WORKER_NODES=$(echo $1 | tr ',' ' ')
                            ;;
    -u | --user )           shift
                            SSH_USER=$1
                            ;;
    -p | --password )       shift
                            SSH_PASSWORD=$1
                            ;;
    -P | --port )           shift
                            SSH_PORT=$1
                            ;;
    -v | --version )        shift
                            unset KUBE_VERSION
                            KUBE_VERSION=$1
                            ;;
    * )                     usage
                            exit 1
  esac
  shift
done


# 启动
if [[ "x${RESET_TAG:-}" == "x1" ]]; then
  reset_all
elif [[ "x${INIT_TAG:-}" == "x1" ]]; then
  start_init
elif [[ "x${ADD_TAG:-}" == "x1" ]]; then
  [[ "$MASTER_NODES" == "127.0.0.1" ]] && MASTER_NODES=""
  add_node
elif [[ "x${DEL_TAG:-}" == "x1" ]]; then
  [[ "$MASTER_NODES" == "127.0.0.1" ]] && MASTER_NODES=""
  del_node
else
  usage
fi
