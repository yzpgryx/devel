## 编译


## 新增软件包
1. cd进package目录，创建自己的目录，根据OpenWrt的Makefile规则编写Makefile, 包括子菜单路径，源码下载地址，编译命令，安装命令等等
2. make menuconfig 配置编译自己新增的软件包
3. make package/mypkg/compile V=s

## 新增启动项
1. 在/etc/init.d/中添加脚本,并添加可执行权限
2. 创建符号链接到/etc/rc.d/
3. /etc/init.d/xxx enable
  ```
  #!/bin/sh /etc/rc.common

  START=99
  STOP=15

  start() {
      echo "Starting modemd..."
      /usr/sbin/modemd -d /dev/ttyUSB2
  }

  stop() {
      echo "Stopping modemd..."
      killall modemd
  }
  ```
