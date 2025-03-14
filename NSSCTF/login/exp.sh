#!/bin/bash

# Ubuntu 18.04 专用Pwn环境搭建脚本
# 支持：pwntools(py3)、libc工具链、ROP工具、调试环境等
# 使用前：chmod +x setup_pwn_18.04.sh && sudo ./setup_pwn_18.04.sh

set -e

# 检查权限和系统版本
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[31m[-] 请使用sudo运行此脚本!\033[0m"
    exit 1
fi

if ! grep -q "Ubuntu 18.04" /etc/os-release; then
    echo -e "\033[31m[-] 此脚本仅适用于Ubuntu 18.04\033[0m"
    exit 1
fi

# 配置颜色和路径
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
RESET='\033[0m'
GLIBC_PATH="/opt/glibc-all-in-one"
LIBC_DB_PATH="/opt/libc-database"

# 更换阿里云镜像源（国内加速）
echo -e "${GREEN}[+] 替换为阿里云Ubuntu 18.04镜像源...${RESET}"
sudo sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
sudo sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

# 安装基础依赖
echo -e "${GREEN}[+] 安装系统依赖...${RESET}"
apt-get update
apt-get install -y \
    python3 python3-pip python3-dev git curl \
    ruby ruby-dev gdb make autoconf \
    openssh-client patchelf file \
    libssl-dev libffi-dev zlib1g-dev \
    libseccomp-dev gcc-multilib

# 修复Python 3.6的pip兼容性问题
echo -e "${GREEN}[+] 配置Python环境...${RESET}"
python3 -m pip install --upgrade pip==20.3.4  # 适配旧版Python 3.6
pip3 install setuptools==44.0.0              # 避免新版不兼容

# 安装pwntools（Python3）
echo -e "${GREEN}[+] 安装pwntools...${RESET}"
pip3 install pwntools==4.9.0                 # 指定兼容版本

# 安装libc工具链
echo -e "${GREEN}[+] 配置libc工具链...${RESET}"

# glibc-all-in-one（使用国内镜像加速）
mkdir -p $GLIBC_PATH
if [ ! -d "$GLIBC_PATH/.git" ]; then
    git clone https://gitee.com/mirrors/glibc-all-in-one.git $GLIBC_PATH
    chmod -R 755 $GLIBC_PATH
fi

# libc-database（国内镜像加速）
mkdir -p $LIBC_DB_PATH
if [ ! -d "$LIBC_DB_PATH/.git" ]; then
    git clone https://gitee.com/mirrors_p/niklasb-libc-database.git $LIBC_DB_PATH
    cd $LIBC_DB_PATH && ./get
    cd -
fi

# 链接LibcSearcher数据库
pip3 install LibcSearcher --no-cache-dir
mkdir -p ~/.libc-database
ln -sf $LIBC_DB_PATH/db ~/.libc-database/db 2>/dev/null || true

# 安装ROP工具链
echo -e "${GREEN}[+] 安装ROP工具...${RESET}"
pip3 install ropper==1.13.5                 # 指定稳定版本
pip3 install ROPgadget==6.3

# 安装one_gadget（修复Ruby 2.5兼容性）
echo -e "${GREEN}[+] 配置Ruby环境...${RESET}"
gem sources --add https://gems.ruby-china.com/ --remove https://rubygems.org/
gem install one_gadget -v 1.8.0             # 指定兼容版本

# 安装调试符号
echo -e "${GREEN}[+] 安装调试符号...${RESET}"
apt-get install -y libc6-dbg
apt-get install -y libc6-dbg:i386           # 兼容32位调试

# 安装pwndbg（修复旧版GDB兼容）
echo -e "${GREEN}[+] 安装pwndbg...${RESET}"
cd ~
if [ ! -d "pwndbg" ]; then
    git clone https://gitee.com/mirrors/pwndbg.git --depth=1
    cd pwndbg
    sed -i 's/^sudo //g' setup.sh           # 移除sudo调用
    ./setup.sh
fi

# 配置环境优化
echo -e "${GREEN}[+] 环境优化...${RESET}"
echo 'export PATH=$PATH:/opt/glibc-all-in-one' >> ~/.bashrc
echo 'alias gdb="gdb -q -ex init-pwndbg"' >> ~/.bashrc  # 自动加载pwndbg

# 完成提示
echo -e "\n${GREEN}[✓] 环境安装完成! 请执行以下操作:${RESET}"
echo -e "${YELLOW}1. 更新环境变量: source ~/.bashrc"
echo -e "2. 验证pwntools: python3 -c 'import pwn'"
echo -e "3. 测试GDB插件: gdb -ex 'py import pwndbg' -ex quit"
echo -e "4. 更新libc数据库: cd /opt/libc-database && ./update${RESET}"