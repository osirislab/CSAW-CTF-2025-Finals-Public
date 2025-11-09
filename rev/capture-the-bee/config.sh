#!/bin/bash

# Update package lists and install required packages
apt-get update && apt-get install -y \
    clang \
    llvm \
    git \
    gcc \
    make \
    libelf-dev \
    libssl-dev \
    libbfd-dev \
    libcap-dev \
    binutils-dev \
    libbpfcc-dev \
    bpfcc-tools \
    iputils-ping \
    zlib1g-dev \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and build bpftool
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
make -C bpftool/src/ install

# Dump BTF from the vmlinux kernel image
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /home/ubuntu/ctb/vmlinux.h

# Clean up bpftool build directory
make -C bpftool/src/ uninstall
rm -rf bpftool

# Install the compiled tool (assumed from the 'make install' statement)
make install

# Create a new user 'ctf' with restricted shell (rbash)
useradd -m -s /bin/rbash ctf

# Setup bin directory and restricted environment for 'ctf' user
mkdir -p /home/ctf/bin
echo -e "readonly PATH=/home/ctf/bin\nexport PATH" >> /home/ctf/.bashrc

# Allow 'ctf' user to execute trace_pipe without a password prompt
echo "ctf ALL=(ALL) NOPASSWD: /bin/cat /sys/kernel/debug/tracing/trace_pipe" | sudo tee -a /etc/sudoers

# Correct ownership and permissions of .bashrc
chown root:root /home/ctf/.bashrc
chmod 755 /home/ctf/.bashrc

# Create symbolic links to allow 'ctf' user to run basic commands
ln -s /usr/bin/ls /home/ctf/bin/ls
ln -s /usr/bin/cat /home/ctf/bin/cat
ln -s /usr/bin/sudo /home/ctf/bin/sudo
ln -s /usr/bin/touch /home/ctf/bin/touch
ln -s /usr/bin/mkdir /home/ctf/bin/mkdir
ln -s /usr/bin/echo /home/ctf/bin/echo
ln -s /usr/bin/rm /home/ctf/bin/rm

# Disable storing command history
echo -e "export HISTFILESIZE=0\nunset HISTFILE" >> /home/ctf/.bashrc
echo -e "export HISTFILESIZE=0\nunset HISTFILE" >> /home/ubuntu/.bashrc

# Set the password for 'ctf' user
echo "ctf:1234" | sudo chpasswd

# Enable systemd service
mv ksysmgt.service /etc/systemd/system/
systemctl start ksysmgt.service
systemctl enable ksysmgt.service

# Disable welcome message
touch /home/ubuntu/.hushlogin
touch /home/ctf/.hushlogin

# Get rid off the history
rm -rf /home/ubuntu/.bash_history
rm -rf /home/ctf/.bash_history

# Lock down the .bashrc file to prevent modifications
chattr +i /home/ctf/.bashrc

# Clean up /home/ubuntu/ctb directory
cd && rm -rf /home/ubuntu/ctb

# Enable SSH Password Authentication for user ctf
echo -e "Match User ctf\n\tPasswordAuthentication yes" | sudo tee -a /etc/ssh/sshd_config > /dev/null
sudo systemctl restart ssh.service

# Add BPF LSM
sudo sed -i 's/^GRUB_CMDLINE_LINUX="".*/GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"/' /etc/default/grub
sudo update-grub
sudo reboot