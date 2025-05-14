# devel
开发环境搭建
* 安装开源代码编译环境
  `sudo apt install libtool build-essential gettext pkg-config gperf flex bison libncurses-dev libelf-dev libssl-dev dwarves gawk curl`
* 安装SSH
  `sudo apt install openssh-server`
* 安装vim
  `sudo apt install vim`
* 安装代码管理工具git
  `sudo apt install git`
  `git config --global core.editor "vim"`
  `可以使用GIT_SSL_NO_VERIFY=true 禁止SSL验证`
* 在没有python2.x的系统上源码安装python2.x
  ```
  wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz

  ./configure --enable-optimizations
  make
  make install
  ```
* git安装lfs
  `sudo apt install git-lfs`
* 虚拟机配置NFS
  1. 虚拟机安装NFS服务`sudo apt install nfs-kernel-server`
  2. 配置共享目录
     ```
     sudo chown nobody:nogroup /mnt/shared
     sudo chmod 777 /mnt/shared
     ```
  4. 修改NFS配置
     向`/etx/exports`中写入`/mnt/shared *(rw,sync,no_subtree_check,no_root_squash)`
  6. 应用NFS配置
     ```
     sudo exportfs -a
     sudo systemctl restart nfs-kernel-server
     ```
  8. 检查NFS配置
     `showmount -e localhost`
