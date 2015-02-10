#!/bin/bash

# Global Variables
openvpn_dir='/etc/openvpn'
easyrsa_dir='/etc/openvpn/easy-rsa'
ovpnkey_dir='/etc/openvpn/easy-rsa/keys'
ovpnsvr_cnf='/etc/openvpn/server.conf'
ovpncrt_dir='/etc/openvpn/certs'
os_distro=$(cat /etc/issue|head -n1|cut -d" " -f1)

# Title Function
func_title(){
  # Clear (For Prettyness)
  clear

  # Print Title
  echo '====================================================================='
  echo ' BuildVPN.sh | [Version]: 1.9.0 | [Updated]: 02.09.2015'
  echo '====================================================================='
}

# OpenVPN Install Function
func_install(){
  func_title
  echo '[*] Updating Package Lists'
  apt-get update

  # Install Packages Based on OS Distribution
  echo '[*] Installing Packages'
  if [ ${os_distro} == 'Debian' ]; then
    apt-get -y install openvpn openssl
  elif [ ${os_distro} == 'Ubuntu' ]; then
    apt-get -y install openvpn openssl easy-rsa
  else
    func_title
    echo
    echo '[!] Error: BuildVPN.sh is only supported on Debian 5+ and Ubuntu 12+.'
    echo
    exit 1
  fi
}

# Server Buildout Function
func_build_server(){
  # Locate RSA Example Directory
  echo '[*] Discovering easy-rsa Directory...'
  easyrsa_fnd=$(find / -name vars|grep easy-rsa|head -n1|sed 's:/vars::')

  # RSA Validation
  if [[ ${easyrsa_fnd} == '' ]]; then
    func_title
    echo
    echo '[!] Error: easy-rsa not installed, re-run with -i option.'
    echo
    exit 1
  fi

  # Get Server Configuration User Input
  func_title
  echo
  read -p 'Enter Server Hostname......................: ' host
  echo
  echo '+----------------------+'
  echo '| Available Interfaces |'
  echo '+----------------------+'
  for if in $(netstat -i|awk 'FNR >= 3 { print $1 }'); do
    ifconfig ${if}|awk '/Link |inet /'|tr -s '[:space:]'|sed -e 's/ Link.*//g' -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f1,2|sed 's/ /\t/'
  done
  echo
  read -p 'Enter IP OpenVPN Server Will Bind To........: ' vpnip
  read -p 'Enter Subnet For VPN (ex: 192.168.100.0)....: ' vpnnet
  read -p 'Enter Subnet Netmask (ex: 255.255.255.0)....: ' netmask
  read -p 'Enter Preferred DNS Server (ex: 8.8.8.8)....: ' dns
  read -p 'Enter Max Client Connection Threshold.......: ' maxconn
  read -p 'Increase Encryption Key Size (y/n)..........: ' incbits

  # Get User Increased Key Size
  if [[ ${incbits} == [yY] ]]; then
    read -p 'Enter Encryption Key Size (ex: 2048)........: ' keysize
  fi

  read -p 'Route All Traffic Through This VPN (y/n)....: ' routeall
  read -p 'Allow Certificates With Same Subject (y/n)..: ' unique
  read -p 'Enter Interface For Masquerading (ex: eth0).: ' natif

  # Build Certificate Authority
  func_title
  echo
  echo '[*] Preparing Directories'

  # Copy Easy-RSA Sample Directory
  cp -R ${easyrsa_fnd} ${easyrsa_dir}
  cd ${easyrsa_dir}

  # Update vars With User Specified Key Size
  if [[ ${incbits} == [yY] ]]; then
    sed -i "s/KEY_SIZE=.*$/KEY_SIZE=${keysize}/g" vars
  fi

  # Create OpenSSL Configuration if Non-Existant
  if [ ! -f openssl.cnf ]; then
    echo '[*] Preparing OpenSSL Configuration'
    cp openssl-1.0.0.cnf openssl.cnf
  fi

  echo '[*] Resetting Variables'
  . ./vars >> /dev/null
  echo '[*] Preparing Build Configurations'
  ./clean-all >> /dev/null
  echo '[*] Building Certificate Authority'
  ./build-ca
  func_title
  echo
  echo '[*] Building Key Server'
  ./build-key-server ${host}
  func_title
  echo
  echo '[*] Generating Diffie Hellman Key'
  ./build-dh
  func_title
  echo
  cd ${ovpnkey_dir}
  echo '[*] Generating TLS-Auth Key'
  openvpn --genkey --secret ta.key

  # Build Server Configuration
  echo "[*] Creating server.conf In ${openvpn_dir}"
  echo "local ${vpnip}" > ${ovpnsvr_cnf}
  echo 'port 1194' >> ${ovpnsvr_cnf}
  echo 'proto udp' >> ${ovpnsvr_cnf}
  echo 'dev tun' >> ${ovpnsvr_cnf}
  echo "ca ${ovpnkey_dir}/ca.crt" >> ${ovpnsvr_cnf}
  echo "cert ${ovpnkey_dir}/${host}.crt" >> ${ovpnsvr_cnf}
  echo "key ${ovpnkey_dir}/${host}.key" >> ${ovpnsvr_cnf}

  # Get DH Key
  dhkey=$(find /etc/openvpn/easy-rsa -name "*dh*.pem")
  echo "dh ${dhkey}" >> ${ovpnsvr_cnf}

  echo "server ${vpnnet} ${netmask}" >> ${ovpnsvr_cnf}
  echo 'ifconfig-pool-persist ipp.txt' >> ${ovpnsvr_cnf}

  # Determine If Route All Traffic Option Was Chosen
  if [[ ${routeall} == [yY] ]]; then
    echo 'push "redirect-gateway def1"' >> ${ovpnsvr_cnf}
  fi

  # Determine If Unique Subjects Option Was Chosen
  if [[ ${unique} == [yY] ]]; then
    echo 'unique_subject = no' >> ${openvpn_dir}/easy-rsa/keys/index.txt.attr
  fi

  echo "push "dhcp-option DNS ${dns}"" >> ${ovpnsvr_cnf}
  echo 'keepalive 10 120' >> ${ovpnsvr_cnf}
  echo "tls-auth ${ovpnkey_dir}/ta.key 0" >> ${ovpnsvr_cnf}
  echo 'comp-lzo' >> ${ovpnsvr_cnf}
  echo "max-clients ${maxconn}" >> ${ovpnsvr_cnf}
  echo 'user nobody' >> ${ovpnsvr_cnf}
  echo 'group nogroup' >> ${ovpnsvr_cnf}
  echo 'persist-key' >> ${ovpnsvr_cnf}
  echo 'persist-tun' >> ${ovpnsvr_cnf}
  echo "status ${openvpn_dir}/status.log" >> ${ovpnsvr_cnf}
  echo "log ${openvpn_dir}/openvpn.log" >> ${ovpnsvr_cnf}
  echo 'verb 3' >> ${ovpnsvr_cnf}
  echo 'mute 20' >> ${ovpnsvr_cnf}
  echo '[*] Enabling IPv4 Forwarding In /etc/sysctl.conf'
  sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sed -i 's/net.ipv4.ip_forward=0/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  echo '[*] Reloading sysctl Configuration'
  /sbin/sysctl -p >> /dev/null 2>&1
  echo '[*] Loading IPTables Masquerading Rule Into Current Ruleset'
  /sbin/iptables -t nat -A POSTROUTING -s ${vpnnet}/${netmask} -o ${natif} -j MASQUERADE
  echo '[*] Adding IPTables Masquerading Rule To /etc/rc.local'
  sed -i "s:^exit 0:/sbin/iptables -t nat -A POSTROUTING -s ${vpnnet}/${netmask} -o ${natif} -j MASQUERADE:" /etc/rc.local
  echo "exit 0" >> /etc/rc.local

  # Finish Message
  echo '[*] Server Buildout Complete'
  echo
  exit 0
}

# Build Client Certificates Function
func_build_client(){
  # Create Certificate Directory If Non-Existant
  if [ ! -d ${ovpncrt_dir} ]; then
    mkdir ${ovpncrt_dir}
  fi

  read -p 'Enter Username (No Spaces)......................: ' user
  read -p 'Enter Name For Configuration File (No Spaces)...: ' confname
  echo
  echo '+------------------------+'
  echo '| Available IP Addresses |'
  echo '+------------------------+'
  for if in $(netstat -i|awk 'FNR >= 3 { print $1 }'); do
    ifconfig ${if}|awk '/Link |inet /'|tr -s '[:space:]'|sed -e 's/ Link.*//g' -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f1,2|sed 's/ /\t/'
  done
  echo
  read -p 'Enter IP/Hostname OpenVPN Server Binds To.......: ' vpnip

  # Build Certificate
  func_title
  echo
  echo "[*] Generating Client Certificate For: ${user}"
  cd ${easyrsa_dir}
  . ./vars
  ./build-key ${user}

  # Prepare Client Build Directory
  cd ${openvpn_dir} && mkdir ${user}

  # Build Client Configuration
  func_title
  echo
  echo '[*] Creating Client Configuration'
  echo 'client' > ${user}/${confname}.ovpn
  echo 'dev tun' >> ${user}/${confname}.ovpn
  echo 'proto udp' >> ${user}/${confname}.ovpn
  echo "remote ${vpnip} 1194" >> ${user}/${confname}.ovpn
  echo 'resolv-retry infinite' >> ${user}/${confname}.ovpn
  echo 'nobind' >> ${user}/${confname}.ovpn
  echo 'persist-key' >> ${user}/${confname}.ovpn
  echo 'persist-tun' >> ${user}/${confname}.ovpn
  echo 'mute-replay-warnings' >> ${user}/${confname}.ovpn
  echo '<ca>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/ca.crt >> ${user}/${confname}.ovpn
  cp ${ovpnkey_dir}/ca.crt ${user}/ca.crt
  echo '</ca>' >> ${user}/${confname}.ovpn
  echo '<cert>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/${user}.crt|awk '!/^ |Certificate:/'|sed '/^$/d' >> ${user}/${confname}.ovpn
  cp ${ovpnkey_dir}/${user}.crt ${user}/${user}.crt
  echo '</cert>' >> ${user}/${confname}.ovpn
  echo '<key>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/${user}.key >> ${user}/${confname}.ovpn
  cp ${ovpnkey_dir}/${user}.key ${user}/${user}.key
  echo '</key>' >> ${user}/${confname}.ovpn
  echo 'ns-cert-type server' >> ${user}/${confname}.ovpn
  echo 'key-direction 1' >> ${user}/${confname}.ovpn
  echo '<tls-auth>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/ta.key|awk '!/#/' >> ${user}/${confname}.ovpn
  cp ${ovpnkey_dir}/ta.key ${user}/ta.key
  echo '</tls-auth>' >> ${user}/${confname}.ovpn
  echo 'comp-lzo' >> ${user}/${confname}.ovpn
  echo 'verb 3' >> ${user}/${confname}.ovpn
  echo 'mute 20' >> ${user}/${confname}.ovpn
  echo 'BuildVPN File Information' >> ${user}/README
  echo >> ${user}/README
  echo 'Certificate Authority Certificate.: ca.crt' >> ${user}/README
  echo 'TLS-Auth Shared Secret Key........: ta.key' >> ${user}/README
  echo "User Certificate..................: ${user}.crt" >> ${user}/README
  echo "User Private Key..................: ${user}.key" >> ${user}/README
  echo "User OpenVPN Profile Bundle.......: ${confname}.ovpn" >> ${user}/README

  # Build Client Tarball
  echo "[*] Creating ${user}-${confname}.tar Configuration Package In: ${ovpncrt_dir}"
  tar -cf ${ovpncrt_dir}/${user}-${confname}.tar ${user}

  # Clean Up Temp Files
  echo '[*] Removing Temporary Files'
  rm -rf ${user}

  # Finish Message
  echo "[*] Client ${user} Buildout Complete"
  echo
  exit 0
}

# Build External-to-Internal Tunnel
# Thanks to Johnny-Nohandle (https://github.com/johnny-nohandle)
func_build_tunnel(){
  # Get Tunnel Configuration User Input
  echo '+----------------------+'
  echo '| Available Interfaces |'
  echo '+----------------------+'
  for if in $(netstat -i|awk 'FNR >= 3 { print $1 }'); do
    ifconfig ${if}|awk '/Link |inet /'|tr -s '[:space:]'|sed -e 's/ Link.*//g' -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f1,2|sed 's/ /\t/'
  done
  echo
  read -p 'Enter External IP The Tunnel Binds To.......: ' etunip
  read -p 'Enter External Port The Tunnel Binds To.....: ' etunport
  read -p 'Enter Internal IP The Tunnel Forwards To....: ' itunip
  read -p 'Enter Internal Port The Tunnel Forwards To..: ' itunport
  read -p 'Enter Protocol The Tunnel Will Use..........: ' tunproto

  # Reconfigure Current IPTables and Save Configuration to Startup
  echo
  echo '[*] Loading IPTables Prerouting Rule Into Current Ruleset'
  /sbin/iptables -t nat -A PREROUTING -p ${tunproto} -d ${etunip} --dport ${etunport} -j DNAT --to-destination ${itunip}:${itunport}
  echo '[*] Adding IPTables Prerouting Rule To /etc/rc.local'
  sed -i "s,^exit 0,/sbin/iptables -t nat -A PREROUTING -p ${tunproto} -d ${etunip} --dport ${etunport} -j DNAT --to-destination ${itunip}:${itunport}," /etc/rc.local
  echo "exit 0" >> /etc/rc.local

  echo
  read -p 'Do You Have Another Tunnel To Add? (y/n)....: ' moretun

  if [[ ${moretun} == [yY] ]]; then
    func_build_tunnel
  else
    echo '[*] Tunnel Buildout Complete'
    echo
    exit 0
  fi
}

# Check Permissions
if [ $(whoami) != 'root' ]; then
  func_title
  echo
  echo '[!] Error: You must run this script with root privileges.'
  echo
  exit 1
fi

# Check OS Version
if [ ${os_distro} == 'Debian' ]; then
  debian_ver=$(cat /etc/debian_version|cut -d"." -f1)
  if [[ ! ${debian_ver} -ge '5' ]]; then
    func_title
    echo
    echo '[!] Error: BuildVPN.sh is only supported on Debian version 5+.'
    echo
    exit 1
  fi
elif [ ${os_distro} == 'Ubuntu' ]; then
  ubuntu_ver=$(cat /etc/issue|head -n1|cut -d" " -f2|cut -d"." -f1)
  if [[ ! ${ubuntu_ver} -ge '12' ]]; then
    func_title
    echo
    echo '[!] Error: BuildVPN.sh is only supported on Ubuntu version 12+.'
    echo
    exit 1
  fi
else
  func_title
  echo
  echo '[!] Error: BuildVPN.sh is only supported on Debian 5+ and Ubuntu 12+.'
  echo
  exit 1
fi


# Select Function and Menu Statement
func_title
case ${1} in
  -i)
    echo
    func_install
    ;;
  -s)
    echo
    func_build_server
    ;;
  -c)
    echo
    func_build_client
    ;;
  -t)
    echo
    func_build_tunnel
    ;;
  *)
    echo
    echo "[Usage]...: ${0} [OPTION]"
    echo '[Options].: -i = Install OpenVPN Packages'
    echo '            -s = Build Server Configuration'
    echo '            -c = Build Client Configuration'
    echo '            -t = Build External-to-Internal Tunnel'
    echo
esac