# 编译linux内核

以ubuntu 20.04编译替换内核为例

1. 生成内核配置文件`.config`
   
   1. 使用当前系统的配置``cp /boot/config-`uname-r` .config``
   
   2. 使用默认配置`make defconfig`

2. 自定义内核配置
   
   1. 关闭debug信息`Kernel hacking` -> `Compile-time checks and compiler options` -> `Compile the kernel with debug info`
   
   2. 打开.config文件，修改`CONFIG_SYSTEM_TRUSTED_KEYS`和`CONFIG_SYSTEM_REVOCATION_KEYS`，改为空值

3. 编译内核
   
   `make -j8`

4. 安装替换
   
   1. 修改`/etc/initramfs-tools/initramfs.conf`文件，`MODULES`的值改为`dep`，默认是`most`会打包所有模块进initramfs，会导致initramfs过大系统无法启动或者启动速度过慢
   
   2. `make modules_install`
   
   3. `make install`
   
   4. `update-grub`


