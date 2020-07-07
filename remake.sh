make
make sdk_install_pkg
make psw_install_pkg
cd linux/installer/bin/
sudo ./sgx_linux_x64_sdk_2.6.100.51363.bin
source /opt/intel/sgxsdk/environment
#cd linux/installer/deb
sudo rm -rf /opt/intel/sgxpsw
sudo ./sgx_linux_x64_psw_2.6.100.51363.bin 
#sudo dpkg -i ./libsgx-urts_2.6.100.51363-xenial1_amd64.deb ./libsgx-enclave-common_2.6.100.51363-xenial1_amd64.deb
