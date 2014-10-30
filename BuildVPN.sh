#!/bin/bash

# Global Variables
easyrsa_fnd=$(find / -wholename "*/easy-rsa/*vars"|sed 's:/vars::')
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
  echo ' BuildVPN.sh | [Version]: 1.6.1 | [Updated]: 10.30.2014'
  echo '================================================================'
}

# Supported OS Function
func_os(){
  # Print Supported OS
  echo
  echo '[ Supported Operating Systems ]'
  echo
  echo ' 1 = Debian-Based.(Versions 5+)'
  echo ' 2 = Ubuntu ......(Versions 12-14)'
  echo ' 3 = RHEL-Based...(Versions 5-6)'
  echo
}

# Server Install Function
func_install(){
  # Attempt OS Auto-Detection
  if [ -f /etc/redhat-release ]; then
    host_os='RHEL'
    epel_ver=$(cat /etc/redhat-release|cut -d" " -f4|cut -d"." -f1)
  else
    host_os=$(cat /etc/issue.net|cut -d" " -f1)
  fi

  # Determine OS
  if [[ ${host_os} == 'Debian' ]] || [[ ${host_os} == 'Ubuntu' ]]; then
    os='1'
  elif [[ ${host_os} == 'RHEL' ]]; then
    os='2'
  else
    echo '[!] Warning: Attempting install on unsupported OS.'
    echo '[!] Installation may still be successful.'
    echo '[!] Please provide the following information.'
    func_os
    read -p 'Enter Operating System.....................: ' os
  fi

  # OpenVPN Installer Statement
  if [ ${os} == '1' ] || [ ${os} == '2' ]; then
    # Install Using Apt-Get (Debian-Based)
    func_title
    echo
    echo '[*] Operating System: Debian-Based'
    echo '[*] Updating Apt Sources'
    apt-get update
    echo
    echo '[*] Installing Packages'
    apt-get -y install openvpn openssl easy-rsa
  elif [ ${os} == '3' ]; then
    # Install Using Yum (RHEL-Based)
    func_title
    echo
    echo '[*] Operating System: RHEL-Based'
    echo
    echo '[ EPEL Repository Required ]'
    echo
    echo ' To install OpenVPN on a RHEL-based OS, EPEL is required.'
    echo
    read -p 'Install EPEL Repository? (y/n)...........: ' epel
    if [ ${epel} == 'y' ]; then
      func_title
      echo
      echo '[*] Installing EPEL Repository'
      case ${epel_ver} in
        5)
          rpm -ivh http://mirrors.kernel.org/fedora-epel/5/i386/epel-release-5-4.noarch.rpm
          ;;
        6)
          rpm -ivh http://fedora-epel.mirror.lstn.net/6/i386/epel-release-6-8.noarch.rpm
          ;;
        7)
          rpm -ivh http://ftp.cse.buffalo.edu/pub/epel/beta/7/x86_64/epel-release-7-0.2.noarch.rpm
          ;;
        *)
          func_title
          echo
          echo '[!] Error: Unsupported RHEL-Based OS Version.'
          echo
          exit 1
      esac
      echo
      echo '[*] Installing Packages'
      yum install openvpn easy-rsa
    else
      func_title
      echo
      echo '[!] Abort: User aborted installation.'
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
  # Get Server Configuration User Input
  read -p 'Enter Server Hostname......................: ' host
  echo
  echo '+----------------------+'
  echo '| Available Interfaces |'
  echo '+----------------------+'
  if [ -f /etc/redhat-release ]; then
    ifconfig|awk "/flags|inet/"|tr -s '[:space:]'|sed -e 's/flags.*//g'|sed -e ':a;N;$!ba;s/\n inet//g'|cut -d" " -f1,3|sed -e 's/ /\t/g'
  else
    ifconfig|awk "/Link |inet /"|tr -s '[:space:]'|sed 's/ Link.*//g'|sed -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f 1,2|sed 's/ /\t/g'|awk '!/lo/'
  fi
  echo
  read -p 'Enter IP OpenVPN Server Will Bind To.......: ' ip
  read -p 'Enter Subnet For VPN (ex: 192.168.100.0)...: ' vpnnet
  read -p 'Enter Subnet Netmask (ex: 255.255.255.0)...: ' netmsk
  read -p 'Enter Preferred DNS Server (ex: 8.8.8.8)...: ' dns
  read -p 'Enter Max Clients Threshold................: ' maxconn
  read -p 'Increase Encryption Key Size (y/n).........: ' incbits

# Get User Increased Key Size
  if [[ ${incbits} == [yY] ]]; then
    read -p 'Enter Encryption Key Size (ex: 2048).......: ' keysize
  fi

  read -p 'Route All Traffic Through This VPN (y/n)...: ' routeall
  read -p 'Allow Certificates With Same Subject (y/n).: ' unique
  read -p 'Enable IP Forwarding (y/n).................: ' forward
  read -p 'Enable IPTables Masquerading (y/n).........: ' enablenat

# Determine What Interface To Use For Masquerading
  if [[ ${enablenat} == [yY] ]]; then
    read -p 'Enter Interface To Use For Masquerading....: ' natif
  fi

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
  echo "local ${ip}" > ${ovpnsvr_cnf}
  echo 'port 1194' >> ${ovpnsvr_cnf}
  echo 'proto udp' >> ${ovpnsvr_cnf}
  echo 'dev tun' >> ${ovpnsvr_cnf}
  echo "ca ${ovpnkey_dir}/ca.crt" >> ${ovpnsvr_cnf}
  echo "cert ${ovpnkey_dir}/${host}.crt" >> ${ovpnsvr_cnf}
  echo "key ${ovpnkey_dir}/${host}.key" >> ${ovpnsvr_cnf}

  # Get DH Key
  dhkey=$(find /etc/openvpn/easy-rsa -name "*dh*.pem")
  echo "dh ${dhkey}" >> ${ovpnsvr_cnf}

  echo "server ${vpnnet} ${netmsk}" >> ${ovpnsvr_cnf}
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

  # Determine Unprivileged Group To Use
  grp_check=$(grep -i "nogroup" /etc/group|wc -l)
  if [ ${grp_check} != '1' ]; then
    echo 'group nobody' >> ${ovpnsvr_cnf}
  fi

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

  # Determine If IPTables NAT Option Was Chosen
  if [[ ${enablenat} == [yY] ]]; then
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
  read -p 'Enter Username (No Spaces).....................: ' user
  read -p 'Enter Name For Configuration File (No Spaces)..: ' confname
  echo
  echo '+------------------------+'
  echo '| Available IP Addresses |'
  echo '+------------------------+'
  if [ -f /etc/redhat-release ]; then
    ifconfig|awk "/flags|inet/"|tr -s '[:space:]'|sed -e 's/flags.*//g'|sed -e ':a;N;$!ba;s/\n inet//g'|cut -d" " -f1,3|sed -e 's/ /\t/g'
  else
    ifconfig|awk "/Link |inet /"|tr -s '[:space:]'|sed 's/ Link.*//g'|sed -e ':a;N;$!ba;s/\n inet//g' -e 's/addr://g'|cut -d" " -f 1,2|sed 's/ /\t/g'|awk '!/lo/'
  fi
  echo
  read -p 'Enter IP/Hostname OpenVPN Server Binds To......: ' ip

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
  echo "remote ${ip} 1194" >> ${user}/${confname}.ovpn
  echo 'resolv-retry infinite' >> ${user}/${confname}.ovpn
  echo 'nobind' >> ${user}/${confname}.ovpn
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
if [ `whoami` != 'root' ]; then
  func_title
  echo
  echo '[!] Error: You must run this script with root privileges.'
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

