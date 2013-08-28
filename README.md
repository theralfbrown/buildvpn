BuildVPN
========

Description
-----------
BuildVPN makes it easy to automate the installation and configuration of OpenVPN servers as well as building client certificates for authentication.
Specifically, it goes through the steps necessary to setup, manage, and maintain OpenVPN servers including:

* Configuring a certificate authority and key server.
* Generating encryption keys Diffie Hellman  and TLS-Auth.
* Creates a server.conf file to meet the needs of your environment.
* Builds client certificate authentication configurations for both *Nix and Windows.

Usage
-----
./BuildVPN.sh [OPTION]

**Supported Switches:**

* -i | --install = Install OpenVPN Packages
* -s | --server  = Build Server Configuration
* -c | --client  = Build Client Configuration
* -u | --update  = Update BuildVPN Script

Supported Operating Systems
---------------------------

* Debian 5-7
* Ubuntu 12.x
