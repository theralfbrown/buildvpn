#!/bin/bash

# Global Variables
openvpn_dir='/etc/openvpn'
easyrsa_dir='/etc/openvpn/easy-rsa'
ovpnkey_dir='/etc/openvpn/easy-rsa/keys'
ovpnsvr_cnf='/etc/openvpn/server.conf'

# Title Function
func_title(){
  # Clear (For Prettyness)
  clear

  # Print Title
  echo '================================================================'
  echo ' BuildVPN.sh | [Version]: 1.5.0 | [Updated]: 01.14.2014'
  echo '================================================================'
}

# Supported OS Function
func_os(){
  # Print Supported OS
  echo '[ Supported Operating Systems ]'
  echo
  echo ' 1 = Debian......(5+)'
  echo ' 2 = Ubuntu......(12+)'
  echo ' 3 = RHEL/CentOS.(6+)'
  echo
}

# Server Install Function
func_install(){
  # Get User Input
  func_os
  read -p 'Enter Operating System.....................: ' os
  # OpenVPN Installer Statement
  if [[ ${os} =~ [1-2] ]]
  then
    # Install Using Apt-Get (Debian-Based)
    func_title
    echo '[*] Updating Apt Sources'
    echo
    apt-get update
    echo
    echo '[*] Installing Packages'
    apt-get -y install openvpn openssl
  elif [ ${os} == '3' ]
  then
    # Install Using Yum (RHEL-Based)
    func_title
    echo
    echo '[ EPEL Repository Required ]'
    echo
    echo ' To install OpenVPN on a RHEL-based OS, EPEL is required.'
    echo
    read -p 'Install EPEL Repository? (y/n)...........: ' epel
    if [ ${epel} == 'y' ]
    then
      func_title
      echo '[*] Installing EPEL Repository'
      rpm -ivh ftp://mirror.cs.princeton.edu/pub/mirrors/fedora-epel/6/i386/epel-release-6-8.noarch.rpm
      echo
      echo '[*] Installing Packages'
      yum install openvpn easy-rsa
    else
      func_title
      echo
      echo '[Error]: User aborted installation.'
      echo
      exit 1
    fi
  else
    # Retry For People Who Don't Read Well
    func_title
    echo
    func_install
  fi
  echo
}

# Server Buildout Function
func_build_server(){
  # Get User Input
  func_os
  read -p 'Enter Operating System.....................: ' os
  # Retry For People Who Don't Read Well
  if [[ ! ${os} =~ [1-3] ]]
  then
    func_title
    echo
    func_build_server
  fi
  read -p 'Enter Server Hostname......................: ' host
  echo
  echo '+----------------------+'
  echo '| Available Interfaces |'
  echo '+----------------------+'
  ifconfig |awk "/Link|inet/"|tr -s '[:space:]'|sed 's/ Link.*//g'|sed -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f 1,2|sed 's/ /\t/g'
  echo
  read -p 'Enter IP OpenVPN Server Will Bind To.......: ' ip
  read -p 'Enter Subnet For VPN (ex: 192.168.100.0)...: ' vpnnet
  read -p 'Enter Subnet Netmask (ex: 255.255.255.0)...: ' netmsk
  read -p 'Enter Preferred DNS Server (ex: 8.8.8.8)...: ' dns
  read -p 'Enter Max Clients Threshold................: ' maxconn
  read -p 'Increase Encryption Key Size To 2048 (y/n).: ' incbits
  read -p 'Route All Traffic Through This VPN (y/n)...: ' routeall
  read -p 'Allow Certificates With Same Subject (y/n).: ' unique
  read -p 'Enable IP Forwarding (y/n).................: ' forward
  # Determine What IP Protocols To Forward For
  if [[ ${forward} == [yY] ]]
  then
    read -p 'Forward IPv4 (y/n).........................: ' forward4
    read -p 'Forward IPv6 (y/n).........................: ' forward6
  fi
  read -p 'Enable IPTables Masquerading (y/n).........: ' enablenat
  # Determine What Interface To Use For Masquerading
  if [[ ${enablenat} == [yY] ]]
  then
    read -p 'Enter Interface To Use For NAT.............: ' natif
  fi

  # Build Certificate Authority
  func_title
  echo
  echo '[*] Preparing Directories'
  # Copy Easy-RSA Sample Directory
  if [[ ${os} =~ [1-2] ]]
  then
    cp -R /usr/share/doc/openvpn/examples/easy-rsa/2.0 ${easyrsa_dir}
  else
    cp -R /usr/share/easy-rsa/2.0 ${easyrsa_dir}
  fi
  cd ${easyrsa_dir}
  # Modify OpenSSL Variables For 2048 Bit Encryption
  if [[ ${incbits} == [yY] ]]
  then
    sed -i 's/KEY_SIZE=1024/KEY_SIZE=2048/g' vars
  fi
  # Workaround For Ubuntu 12.x
  if [ ${os} == '2' ]
  then
    echo '[*] Preparing Ubuntu Config File'
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
  echo "local ${ip}" > ${ovpnsvr_cnf}
  echo 'port 1194' >> ${ovpnsvr_cnf}
  echo 'proto udp' >> ${ovpnsvr_cnf}
  echo 'dev tun' >> ${ovpnsvr_cnf}
  echo "ca ${ovpnkey_dir}/ca.crt" >> ${ovpnsvr_cnf}
  echo "cert ${ovpnkey_dir}/${host}.crt" >> ${ovpnsvr_cnf}
  echo "key ${ovpnkey_dir}/${host}.key" >> ${ovpnsvr_cnf}
  # Determine If Increased Key Size Option Was Chosen
  if [[ ${incbits} == [yY] ]]
  then
    echo "dh ${ovpnkey_dir}/dh2048.pem" >> ${ovpnsvr_cnf}
  else
    echo "dh ${ovpnkey_dir}/dh1024.pem" >> ${ovpnsvr_cnf}
  fi
  echo "server ${vpnnet} ${netmsk}" >> ${ovpnsvr_cnf}
  echo 'ifconfig-pool-persist ipp.txt' >> ${ovpnsvr_cnf}
  # Determine If Route All Traffic Option Was Chosen
  if [[ ${routeall} == [yY] ]]
  then
    echo 'push "redirect-gateway def1"' >> ${ovpnsvr_cnf}
  fi
  # Determine If Unique Subjects Option Was Chosen
  if [[ ${unique} == [yY] ]]
  then
    echo 'unique_subject = no' >> ${openvpn_dir}/easy-rsa/keys/index.txt.attr
  fi
  echo "push "dhcp-option DNS ${dns}"" >> ${ovpnsvr_cnf}
  echo 'keepalive 10 120' >> ${ovpnsvr_cnf}
  echo "tls-auth ${ovpnkey_dir}/ta.key 0" >> ${ovpnsvr_cnf}
  echo 'comp-lzo' >> ${ovpnsvr_cnf}
  echo "max-clients ${maxconn}" >> ${ovpnsvr_cnf}
  echo 'user nobody' >> ${ovpnsvr_cnf}
  # Determine Unprivileged Group To Use
  if [ ${os} == '3' ]
  then
    echo 'group nobody' >> ${ovpnsvr_cnf}
  else
    echo 'group nogroup' >> ${ovpnsvr_cnf}
  fi
  echo 'persist-key' >> ${ovpnsvr_cnf}
  echo 'persist-tun' >> ${ovpnsvr_cnf}
  echo "status ${openvpn_dir}/status.log" >> ${ovpnsvr_cnf}
  echo "log ${openvpn_dir}/openvpn.log" >> ${ovpnsvr_cnf}
  echo 'verb 3' >> ${ovpnsvr_cnf}
  echo 'mute 20' >> ${ovpnsvr_cnf}

  # Determine If IPv4 Forwarding Option Was Chosen
  if [[ ${forward4} == [yY] ]]
  then
    echo '[*] Enabling IPv4 Forwarding In /etc/sysctl.conf'
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sed -i 's/net.ipv4.ip_forward=0/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    echo '[*] Reloading sysctl Configuration'
    /sbin/sysctl -p >> /dev/null 2>&1
  fi

  # Determine If IPv6 Forwarding Option Was Chosen
  if [[ ${forward6} == [yY] ]]
  then
    echo '[*] Enabling IPv6 Forwarding In /etc/sysctl.conf'
    sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
    sed -i 's/net.ipv6.conf.all.forwarding=0/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
    echo '[*] Reloading sysctl Configuration'
    /sbin/sysctl -p >> /dev/null 2>&1
  fi

  # Determine If IPTables NAT Option Was Chosen
  if [[ ${enablenat} == [yY] ]]
  then
    echo '[*] Loading IPTables Masquerading Rule Into Current Ruleset'
    /sbin/iptables -t nat -A POSTROUTING -o ${natif} -j MASQUERADE
    echo '[*] Adding IPTables Masquerading Rule To /etc/rc.local'
    sed -i "s:exit 0:/sbin/iptables -t nat -A POSTROUTING -o ${natif} -j MASQUERADE:" /etc/rc.local
    echo "exit 0" >> /etc/rc.local
  fi

  # Finish Message
  echo '[*] Server Buildout Complete'
  echo
  exit 0
}

# Build Client Certificates Function
func_build_client(){
  # Get User Input
  func_os
  # Retry For People Who Don't Read Well
  read -p 'Enter Operating System.........................: ' os
  if [[ ! ${os} =~ [1-3] ]]
  then
    func_title
    echo
    func_build_client
  fi
  read -p 'Enter Username (No Spaces).....................: ' user
  read -p 'Enter Name For Configuration File (No Spaces)..: ' confname
  echo
  echo '+------------------------+'
  echo '| Available IP Addresses |'
  echo '+------------------------+'
  ifconfig |awk "/Link|inet/"|tr -s '[:space:]'|sed 's/ Link.*//g'|sed -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f 1,2|sed 's/ /\t/g'
  echo
  read -p 'Enter IP/Hostname OpenVPN Server Binds To......: ' ip
  read -p 'Will This Client Run Under Windows (y/n).......: ' windows
  # Additional Configuration For Windows Clients
  if [[ ${windows} == [yY] ]]
  then
    read -p 'Enter Node Name (Required For Windows Clients).: ' node
  fi

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
  # Determine If Windows Options Were Chosen
  if [[ ${windows} == [yY] ]]
  then
    echo "dev-node ${node}" >> ${user}/${confname}.ovpn
  fi
  echo 'proto udp' >> ${user}/${confname}.ovpn
  echo "remote ${ip} 1194" >> ${user}/${confname}.ovpn
  echo 'resolv-retry infinite' >> ${user}/${confname}.ovpn
  echo 'nobind' >> ${user}/${confname}.ovpn
  # Set Unprivileged User & Group For Linux Clients
  if [[ ${windows} != [yY] ]]
  then
    echo 'user nobody' >> ${user}/${confname}.ovpn
    if [ ${os} == '3' ]
    then
      echo 'group nobody' >> ${user}/${confname}.ovpn
    else
      echo 'group nogroup' >> ${user}/${confname}.ovpn
    fi
  fi
  echo 'persist-key' >> ${user}/${confname}.ovpn
  echo 'persist-tun' >> ${user}/${confname}.ovpn
  echo 'mute-replay-warnings' >> ${user}/${confname}.ovpn
  echo '<ca>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/ca.crt >> ${user}/${confname}.ovpn
  echo '</ca>' >> ${user}/${confname}.ovpn
  echo '<cert>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/${user}.crt|awk '!/^ |Certificate:/'|sed '/^$/d' >> ${user}/${confname}.ovpn
  echo '</cert>' >> ${user}/${confname}.ovpn
  echo '<key>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/${user}.key >> ${user}/${confname}.ovpn
  echo '</key>' >> ${user}/${confname}.ovpn
  echo 'ns-cert-type server' >> ${user}/${confname}.ovpn
  echo 'key-direction 1' >> ${user}/${confname}.ovpn
  echo '<tls-auth>' >> ${user}/${confname}.ovpn
  cat ${ovpnkey_dir}/ta.key|awk '!/#/' >> ${user}/${confname}.ovpn
  echo '</tls-auth>' >> ${user}/${confname}.ovpn
  echo 'comp-lzo' >> ${user}/${confname}.ovpn
  echo 'verb 3' >> ${user}/${confname}.ovpn
  echo 'mute 20' >> ${user}/${confname}.ovpn

  # Build Client Tarball
  echo "[*] Creating ${user}-${confname}.tar Configuration Package In: ${openvpn_dir}"
  tar -cf ${user}-${confname}.tar ${user}

  # Clean Up Temp Files
  echo '[*] Removing Temporary Files'
  rm -rf ${user}

  # Finish Message
  echo "[*] Client ${user} Buildout Complete"
  echo
  exit 0
}

# Check Permissions
if [ `whoami` != 'root' ]
then
  func_title
  echo
  echo '[Error]: You must run this script with root privileges.'
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
  *)
    echo
    echo "[Usage]...: ${0} [OPTION]"
    echo '[Options].:'
    echo '            -i = Install OpenVPN Packages'
    echo '            -s = Build Server Configuration'
    echo '            -c = Build Client Configuration'
    echo
esac
