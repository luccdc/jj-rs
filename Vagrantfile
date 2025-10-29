# -*- mode: ruby -*-
# vi: set ft=ruby :

$set_environment_variables = <<SCRIPT
tee "/etc/profile.d/myvars.sh" >/dev/null <<EOF
export PATH="/jj/x86_64-unknown-linux-musl/debug:$PATH"
EOF
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.define "rocky9" do |rocky|
    rocky.vm.box = "generic/rocky9"

    rocky.vm.provision "shell", inline: $set_environment_variables, run: "always"

    rocky.vm.synced_folder ".", "/vagrant", disabled: true
    rocky.vm.synced_folder "./target", "/jj", type: "nfs", nfs_version: 4
    rocky.vm.network "private_network", ip: "192.168.56.2"
  end

  config.vm.define "debian12" do |debian|
    debian.vm.box = "debian/bookworm64"

    debian.vm.provision "shell", inline: $set_environment_variables, run: "always"

    debian.vm.synced_folder ".", "/vagrant", disabled: true
    debian.vm.synced_folder "./target", "/jj"

    debian.vm.network "private_network", ip: "192.168.56.3"
  end

  config.vm.define "ubuntu24.04" do |ubuntu|
    ubuntu.vm.box = "ubuntu/bionic64"

    ubuntu.vm.provision "shell", inline: $set_environment_variables, run: "always"

    ubuntu.vm.synced_folder ".", "/vagrant", disabled: true
    ubuntu.vm.synced_folder "./target", "/jj", type: "nfs", nfs_version: 4

    ubuntu.vm.network "private_network", ip: "192.168.56.4"
  end

  config.vm.define "alpine" do |alpine|
    alpine.vm.box = "generic/alpine312";

    alpine.vm.provision "shell", inline: $set_environment_variables, run: "always"

    alpine.vm.synced_folder ".", "/vagrant", disabled: true
    alpine.vm.synced_folder "./target", "/jj", type: "nfs", nfs_version: 4

    alpine.vm.network "private_network", ip: "192.168.56.4"
  end
end
