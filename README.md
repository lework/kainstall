# kainstall  = kubeadm install
基于kubeadmin一键部署kubernetes集群



## Why

为什么要搞这个？ansible playbook 不好么？

>因为**懒**，ansible playbook编排是非常给力的，不过需要安装python和ansible。因为**懒**，我想要个更简单的方式来快速部署一个分布式的 kubernetes ha集群， 使用 shell 脚本可以不借助外力直接在服务器上运行，省时省力。



## Require

OS: `centos 7.x`

CPU: `2C`

MEM: `2G`



## Usage

下载脚本

```bash
wget https://cdn.jsdelivr.net/gh/lework/kainstall@master/kainstall.sh
```



帮助信息

```bash
bash kainstall.sh 
Install kubernetes cluster using kubeadm.

Usage: kainstall.sh init|reset [-m master] [-w worker] [-u user] [-p password] [-P port] [-v version]
  -m,--master     master node, default: 127.0.0.1
  -w,--worker     work node, default: ''
  -u,--user       ssh user, default: root
  -p,--password   ssh password,default: 123456
  -P,--port       ssh port, default: 22
  -v,--version    kube version , default: 1.19.2


Example:
  [init] node
  kainstall.sh init \
  --master 192.168.77.130,192.168.77.131,192.168.77.132  \
  --worker 192.168.77.133,192.168.77.134,192.168.77.135 \
  --user root \
  --password 123456 \
  --version 1.19.2\

  [reset] node
  kainstall.sh reset \
  --master 192.168.77.130,192.168.77.131,192.168.77.132  \
  --worker 192.168.77.133,192.168.77.134,192.168.77.135 \
  --user root \
  --password 123456 \
  --version 1.19.2\


  See detailed log >>> /tmp/tmp.o1vc5Lv8V8 
```



初始化集群

```bash
bash kainstall.sh init \
  --master 192.168.77.130,192.168.77.131,192.168.77.132 \
  --worker 192.168.77.133,192.168.77.134 \
  --user root \
  --password 123456 \
  --port 22 \
  --version 1.19.2
```



重置集群

```bash
bash kainstall.sh reset \
  --master 192.168.77.130,192.168.77.131,192.168.77.132 \
  --worker 192.168.77.133,192.168.77.134 \
  --user root \
  --password 123456 \
  --port 22 \
```

