BuildVPN
========

Description
-----------
BuildVPN makes it easy to automate the installation and configuration of OpenVPN servers and building client certificates for authentication.
Specifically, it goes through the steps necessary to setup, manage, and maintain OpenVPN servers including:

* Configuring a certificate authority and key server.
* Generating Diffie Hellman and TLS-Auth encryption keys.
* Creates a server.conf file to meet the needs of your environment.
* Builds client certificate authentication configurations for both Linux and Windows platforms.

Usage
-----
**Running BuildVPN**

 ./BuildVPN.sh [OPTION]

**Supported Switches:**

* -i = Install OpenVPN Packages
* -s = Build Server Configuration
* -c = Build Client Configuration
* -t = Build External-to-Internal Tunnel

Supported Operating Systems
---------------------------
* Debian 5+
