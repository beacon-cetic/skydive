# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "bento/ubuntu-16.04"

  config.vm.network "private_network", ip: "192.168.33.10"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "8096"
  end


  config.vm.provision "shell", privileged: false, inline: <<-SHELL
     sudo apt-get update -y
     sudo add-apt-repository ppa:openjdk-r/ppa -y
     sudo apt-get update -y
     sudo apt-get install -y openjdk-7-jdk
     git clone https://git.openstack.org/openstack-dev/devstack -b stable/newton
     cp /vagrant/local.conf devstack/local.conf
     ./devstack/stack.sh
     git clone https://github.com/voyageur/openstack-scripts.git -b sfc_newton_demo
     #./openstack-scripts/simple_sfc_vms.sh
  SHELL
end
