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
