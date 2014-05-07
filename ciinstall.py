#!/usr/bin/python   

#########################################################################################
#
# Copyright (C) 2013 Collective Industries code provided by Levi Modl & Andrew Malone
# Python code for installing all the possible programs we use the most
#
#########################################################################################

###############################################################################
#  TODO:
#  Add ulogd config                                                            
#  Add iptables firewall script (set default as SSH on 22 only from localnet)  
#  Add mysql database + user for firewall                                      
#  Add firewall parser (webfwlog) + config (/etc/webfwlog.conf)       
#  Add config section for modifying config files
#  Add in service dictionary parser menu API
###############################################################################

########################
#
#  Importing Packages
#
########################
from subprocess import call
import os
import subprocess
import shlex
import getpass
import time
import urllib2
import os.path
import glob
import platform
import crypt
import urllib2
import re
import grp

########################
#
#  Package Installation
#  Check & Install
#
########################
global arc 
global User

npy = subprocess.call(shlex.split('locate npyscreen-3.6.egg-info')) # Checks to see if npyscreen is installed
PyPIP = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" python-pip')) # Checks to see if python PIP is installed
Clint = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" clint')) # Checks to see if clint is installed
SPC = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" software-properties-common')) # Checks to see if software-properties-common is installed
SPP = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" python-software-properties')) # Checks to see if python-software-properties is installed
AF = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" apt-file')) # Checks to see if apt-file is installed
# P3 = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" python3.3')) # Check to see if python 3.3 is installed
arc = platform.architecture()[0] # Checks to see if the system is running i386 or x64 version
User = getpass.getuser() # Gets the current username 

# Installing npyscreen
if npy == 1:
    os.chdir('/opt/')
    subprocess.call(shlex.split('sudo wget https://pypi.python.org/packages/source/n/npyscreen/npyscreen-3.6.tar.gz --no-check-certificate'))
    subprocess.call(shlex.split('sudo tar xvf npyscreen-3.6.tar.gz'))
    os.chdir('npyscreen-3.6')
    subprocess.call(shlex.split('sudo ./setup.py install'))
    subprocess.call(shlex.split('sudo rm /opt/npyscreen-3.6.tar.gz'))
import npyscreen

# Python PIP Installation
if PyPIP ==  1:
    subprocess.call(shlex.split('sudo apt-get install -y python-pip'))
    
# Clint Installation
if Clint == 1:
    subprocess.call(shlex.split('sudo pip install clint'))
    
# software-properties-common Installation
if SPC == 1:
    subprocess.call(shlex.split('sudo apt-get install -y software-properties-common'))    

# software-properties-common Installation
if SPP == 1:
    subprocess.call(shlex.split('sudo apt-get install -y python-software-properties'))    
	
# apt-file Installation and Update	
if AF == 1:
    subprocess.call(shlex.split('sudo apt-get install -y apt-file && apt-file update'))

########################
#
#  Global Variables
#
<<<<<<< HEAD
########################
arc = '' # Variable for the machines architecture
User = '' # Variable for getting the user who is running this script
IP = '' # Variable for getting the external IP of the server
choice = '' # Variable for program choises on the menu
######################
# Firewall Variables #
######################
target_Dlog = 'log_drop' # Silently Drop + Log
target_Alog = 'log_accept'
target_Rlog = 'log_reject' # Returns ACMP Admin Prohibited + Log
####################
# Dictionary Array #
####################
=======
##########################################

### Firewall API ###
# set of firewall  #
# functions calls  #
# iptables with    #
# ports to add to  #
# the firewall and #
# sets log options #
# if needed        #
#############################################
# PROVIDED BY: Andrew Malone                #
# COPYRIGHT: Collective Industries (C) 2014 #
#############################################

def pre_fw_init(fw_log_typ):
	# Call once to set up standard firewall rule-set and prepare for server install
	if fw_log_typ == 1:
                subprocess.call(shlex.split("sudo ./obj/firewall/basic-ulogd.fw")) ## 1 == User Logging Daemon 0 == SYSLOG logging space
        if fw_log_typ == 0:
                subprocess.call(shlex.split("sudo ./obj/firewall/basic-syslog.fw"))# install basic firewall all other rules will be built ON TOP of this script

	subprocess.call(shlex.split("sudo iptables -N "+target_Dlog)) ## add drop + log chain to firewall
	subprocess.call(shlex.split("sudo iptables -N "+target_Alog)) ## add Accept + log chain to firewall
	## Add basic log options to bolth chains this is also depends on the logging daemon ##
	if fw_log_typ == 0:
		subprocess.call(shlex.split("sudo iptables -A "+target_Dlog+" -j ULOG --ulog-nlgroup 1 --ulog-prefix \"DENY\" --ulog-qthreshold 1"))
		subprocess.call(shlex.split("sudo iptables -A "+target_Dlog+" -j DROP"))
	        subprocess.call(shlex.split("sudo iptables -A "+target_Alog+" -j ULOG --ulog-nlgroup 1 --ulog-prefix \"ACCEPT\" --ulog-qthreshold 1"))
        	subprocess.call(shlex.split("sudo iptables -A "+target_Alog+" -j ACCEPT"))
	if fw_log_typ == 1:
            subprocess.call(shlex.split("sudo iptables -A "+target_Dlog+" -j LOG  --log-level info --log-prefix \"DENY\""))
            subprocess.call(shlex.split("sudo iptables -A "+target_Dlog+" -j DROP"))
            subprocess.call(shlex.split("sudo iptables -A "+target_Alog+" -j LOG  --log-level info --log-prefix \"ACCEPT\""))
            subprocess.call(shlex.split("sudo iptables -A "+target_Alog+" -j ACCEPT")) 
		
def topt(option):
	# Parses List of Options and returns the iptables Target
	if option == "A":
		return "ACCEPT"
	if option == "D":
		return "DROP"
	if option == "A+L":
		return target_Alog
	if option == "D+L":
		return target_Dlog
	if option == "R+L":
		return target_Rlog
	else: #tell user about wrong option and failsafe to REJECT no log
		if option != "R":
	                print "[ERROR]:topt():%s:unknown target using REJECT" % (option)
        	return "REJECT"
# UDP packet handler
def fw_udp(port,target_opt):
	# UDP packets from port (DROP/ACCEPT/REJECT) + LOG
	subprocess.call(shlex.split("sudo iptables -A INPUT -p udp -m udp --dport "+port+" -m state --state NEW -j "+topt(target_opt)))

# TCP Packet Handler
def fw_tcp(port,target_opt):
	# TCP packets from port (DROP/ACCEPT/REJECT) + LOG
	subprocess.call(shlex.split("sudo iptables -A INPUT -p tcp -m tcp --dport "+port+" -m state --state NEW -j "+topt(target_opt)))

# Dictionary Array of services: "TCP|UDP:port_numbers:OPTIONS" allows for editing each building rules
>>>>>>> 0f8fb9cb72a3afcb90b9b6b9e200fd7982c53591
fw_services = {
		"mangos-world": "TCP:8085:A",	# defualt for mangos-world accept on tcp 8085
		"mangos-auth": 	"TCP:3724:A",	# mangos "REALMD" authentication server
		"IceCast2": 	"TCP:8000:A",	# Icecast2 TCP 8000
		"TS3-FS":	"TCP:30033:A",  # TeamSpeak3 FileServer
		"TS3-Voice":	"UDP:9987:A",	# TeamSpeak3 Voice Server
		"TS3-Query":	"TCP:10011:A",	# TeamSpeak3 QueryServer
		"HTTP":		"TCP:80:A",     # HTTP Server (Apache2)
		"HTTPS":	"TCP:443:A",    # HTTPS Server (apache2)
		"webmin":	"TCP:10000:A+L",# WebMin Server
		"mysql":	"TCP:3306:A",	# MYSQL Server
		"pop3":		"TCP:110:A",	# POP3 Email port
		"pop3s":	"TCP:995:A",	# POP3 Secured port
		"smtp":		"TCP:25:A",	# SMTP Email Port
		"smtps":	"TCP:465:A",	# SMTP Secure Email
		"samba":	"TCP:445:A",	# SAMBA windows file share  
		"netbios-ssn":	"UDP:139:A",	# SAMBA windows share netbios-ssn
		"netbios-dgm":	"UDP:138:A",	# port 138 UDP netbios-dgm for SAMBA
		"netbios-ns":	"UDP:137:A",	# netbios-ns 
		"minecraft":	"TCP:65535:A",	# Minecraft TCP Port
		"LDAP":		"TCP:389:A",	# LDAP server port
		"LDAP-GC":	"TCP:3268:A",	# LDAP Global Catalog
		"LDAP-GC-SSL":	"TCP:3269:A",	# LDAP GC SSL
		"LDAPS":	"TCP:636:A"	# LDAP Secured
		}
########################
# Program Install List #
########################
pinstall = ['Teamspeak 3',
            'No-IP',
            'Webmin',
            'PHPMyAdmin',
            'Java',
            'Virtual Box',
            'PHPBB3',
            'Bind9'
            'gitHub',
            'Beep',
            'UlogD',
            'Add Admin']
            
########################
#
#  Functions
#
########################
################
# Firewall API #
################
def pre_fw_init(fw_log_typ):
    # Call once to setup standard firewall rule-set and prepare for server install
    if fw_log_typ == 1:
        subprocess.call(shlex.split('sudo ./obj/firewall/basic-ulogd.fw')) # 1 == User Logging Daemon
        if fw_log_typ == 0:
            subprocess.call(shlex.split('sudo ./obj/firewall/basic-syslog.fw')) # Install basic firewall all other rules will be built ON TOP of this script
        
    subprocess.call(shlex.split('sudo iptables -N ' + target_Dlog)) # Add drop + log chain to firewall
    subprocess.call(shlex.split('sudo iptables -N ' + target_Alog)) # Add Accept + log chain to firewall
    # Add basic log options to both chains this is also depends on the logging deamon
    if fw_log_typ == 0:
        subprocess.call(shlex.split('sudo iptables -A ' + target_Dlog + ' -j ULOG --ulog-nlgroup 1 --ulog-prefix \"DENY\" --ulog-qthreshold 1'))
		subprocess.call(shlex.split('sudo iptables -A ' + target_Dlog + ' -j DROP'))
        subprocess.call(shlex.split('sudo iptables -A ' + target_Alog + ' -j ULOG --ulog-nlgroup 1 --ulog-prefix \"ACCEPT\" --ulog-qthreshold 1'))
        subprocess.call(shlex.split('sudo iptables -A ' + target_Alog + ' -j ACCEPT'))
	if fw_log_typ == 1:
        subprocess.call(shlex.split('sudo iptables -A ' + target_Dlog + ' -j LOG  --log-level info --log-prefix \"DENY\"'))
        subprocess.call(shlex.split('sudo iptables -A ' + target_Dlog + ' -j DROP'))
        subprocess.call(shlex.split('sudo iptables -A ' + target_Alog + ' -j LOG  --log-level info --log-prefix \"ACCEPT\"'))
        subprocess.call(shlex.split('sudo iptables -A ' + target_Alog + ' -j ACCEPT')) 
        
def topt(option):
    # Parses List of Options and returns the iptables Target
    if option == 'R':
        return 'REJECT'
    if option == 'A':
        return 'ACCEPT'
    if option == 'D':
        return 'DROP'
    if option == 'A+L':
        return target_Alog
    if option == 'D+L':
        return target_Dlog
    if option == 'R+L':
        return target_Rlog

# UDP Packet Handler
def fw_udp(port, target_opt):
    # UDP packets from port (DROP/ACCEPT/REJECT) + LOG
    if target != 'A' or target != 'D' or target != 'R' or target != 'A+L' or target != 'D+L' or target != 'R+L':
        print '[ERROR:fw_tcp():%s:unknown target using REJECT' % (target)
    subprocess.call(shlex.split('sudo iptables -A INPUT -p udp -m --dport ' + port + ' -m  state --state NEW -j ' + topt(target_opt)))

# TCP Packet Handler
def fw_tcp(port, target_opt):
        # TCP packets from port (DROP/ACCEPT/REJECT) + LOG
        if target != 'A' or target != 'D' or target != 'R' or target != 'A+L' or target != 'D+L' or target != 'R+L':
            print '[ERROR]:fw_tcp():%s:unknown target using REJECT' % (target)
            target = 'R' # Set REJECT flag
        subprocess.call(shlex.split('sudo uptables -A INPUT -p tcp -m tcp --dport ' + port + ' -m state --state NEW -j ' + topt(target_opt)))
 
# Firewall Writer
def fw_write():
    # Write installed programs to firewall
    for service, option in fw_services.iteritems():
        opt_lst = options.split(':') # Split on the Colon
        print '[FW] ADDING servicename %s %s port %s TARGET: %s' % (service, opt_lst[0], opt_lst[1], topt(opt_lst[2]))
        if opt_lst[0] == 'TCP':
            fw_tcp(opt_lst[1], opt_lst[2])
        if opt_lst[0] == 'UDP':
            fw_tcp(opt_lst[1], opt_lst[2])
        
# Configuration File Writer
## PROVIDED BY: Andrew Malone
## COPYRIGHT: Collective Industries (C) 2014
def write_conf(in_file_n, out_file_n):
    # Open in_file_n and install it to out_file_n back up old one first
    subprocess.call(shlex.split('cp ' + out_file_n + ' ' + out_file_n + '.bak')) # Add .bak to the filename provided
    with open(in_file_n, 'r') as infile: # Open the file and catch errors as an exception
        with open(out_file_n, 'w') as outfile:
            for i, line in enumerate(infile):
                outfile.write(line) # Write file line by line
                
# Collective Industries Debug
def debug(var, msg, DEBUG):
    if DEBUG == '1':
        if var != '':
            print msg
        elif var == '':
            print var + ' = ' + msg
        raw_input('Hit any key to continue')
        
# Gets External IP Address of server
def chkip()
    global IP
    url = 'http://checkip.dyndns.org'
    request = urllib.urlopen(url).read()
    theIP = re.findall(r'\d{1,3}\.\d{1,3}.\d{1.3}', request)
    IP = theIP[0]

##############################   
# Collective Industries Logo #
##############################
def logo():
    print ''
	print ' CCCCC       IIIIIIIII'
	print 'CCC CCC         III'
	print 'CCC CCC         III'
	print 'CCC             III'
	print 'CCC     ====    III'
	print 'CCC     ====    III'
	print 'CCC             III'
	print 'CCC CCC         III'
	print 'CCC CCC         III'
	print ' CCCCC       IIIIIIIII   http://ci-main.no-ip.org/'
	print ''
########################
#
#  Menu
#
########################
class InstallApp(npyscreen.NPSApp): # Simple UI Menu class by nypscreen
    def main(self):
    Form = nypscreen.ActionForm(name = 'Collective Industries Program Installation')
    
    ###################################
    # Programs to Add:
    # iptables firewall rule builder
    # Mangos-Enhanced
    # LHC
    # Icinga + configuration
    # Moodle - staff training program
    # phpLDAPAdmin
    # UlogD + configuration of database and iptables
    # ClamAV + daemon
    # Mangos + compile install configuration and dameon
    # MySQL Replication
    # System backup + cron tab with full script bash and automated backup
    # Beep
    # Beep Melodies
    ###################################
    
    # This creates the option and names
    choice = Form.add(npyscreen.TitleMultiSelect, max_height = -2, value = [], name 'Pick the programs you want to install',
        values = pinstall, scroll_exit = True)
        
    def on_cancel():
        exit()
        
    Form.on_cancel = on_cancel
    
    Form.edit() # The allows the person to edit the menu
    
########################
#
#  Program Installation
#
########################
install():
    ###############
    # Teamspeak 3 #
    ###############
    for sel in choice.get_selected_objects():
        if sel == 'Teamspeak 3':
            subprocess.call('clear')
            logo()
            print 'Installing Teamspeak3'
            if str(arc) == '64bit':
                subprocess.call(shlex.split('sudo wget http://ftp4players.de/pub/hosted/ts3/releases/3.0.10.3/teamspeak3-server_linux-amd64-3.0.10.3.tar.gz')) # Downloads 64 bit Teamspeak 3 server
                subprocess.call(shlex.split('sudo tar xzf treamspeak3-server_linux-amd64-3.0.10.3.tar.gz')) # Un compresses file
                subprocess.call(shlex.split('sudo tar xzf teamspeak3-server_linux-amd64-3.0.10.3.tar.gz')) # Un compresses file
                subprocess.call(shlex.split('sudo adduser --disabled-login teamspeak3')) # Creates user with no password
                subprocess.call(shlex.split('sudo mv teamspeak3-server_linux-amd64 /usr/local/teamspeak3')) # Moves the Teamspeak folder to a new location

            elif str(arc) == '32bit':
                debug('arc', str(arc), '1')
                subprocess.call(shlex.split('wget http://ftp.4players.de/pub/hosted/ts3/releases/3.0.10.3/teamspeak3-server_linux-x86-3.0.10.3.tar.gz')) # Downloads 32 bit Teamspeak 3 server
                subprocess.call(shlex.split('sudo tar xzf tamespeak3-server_linux-x86-3.0.10.3.tar.gz')) # Un compresses file
                subprocess.call(shlex.split('sudo adduser --disabled-login teamspeak3')) # Creates user with no password
                subprocess.call(shlex.split('sudo mv teamspeak3-server_linux-x86 /usr/local/teamspeak3')) # Moves the eamspeak folder to a new location
		
            subprocess.call(shlex.split('sudo chown -R teamspeak3 /usr/local/teamspeak3')) # Sets the owner to the teamspeak 3 folder to the user teamspeak3
            subprocess.call(shlex.split('sudo ln -s /usr/local/teamspeak3/ts3server_startupscript.sh /etc/init.d/teamspeak3'))
            subprocess.call(shlex.split('sudo update-rc.d teamspeak3 defaults')) # Adds the Teamspeak 3 server to the startup command
            subprocess.call(shlex.split('sudo service teamspeak3 start')) # Starts the Teamspeak 3 server
		
            # Opens up the ports in iptabels needed for Teamspeak 3
            Firewall = raw_input('Open ports in your firewall for Teamspeak 3?: [y]' )#make TS3 rule and TARGET chain for cleaner table
            if Firewall == 'y' or Firewall == '':
                # Firewall function call
                print "Opening ports"
                subprocess.call(shlex.split('sudo iptables -A INPUT -p udp --dport 9987 -j ACCEPT'))
                subprocess.call(shlex.split('sudo iptables -A INPUT -p udp --sport 9987 -j ACCEPT'))#check source ports do we need them? or is it arbitrary
                print "Port 9987 now open"
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --dport 30033 -j ACCEPT'))
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --sport 30033 -j ACCEPT'))
                print "Port 30033 now open"
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --dport 10011 -j ACCEPT'))
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --sport 10011 -j ACCEPT'))
                print "Port 10011 now open"
    #########
    # No-IP #
    #########
    for sel in choice.get_selected_objects():
        if sel == 'No-IP':
            subprocess.call('clear')
            logo()
            print 'Installing No-IP'
            subprocess.call(shlex.split('sudo apt-get install -y build-essential checkinstall')) # Installs build-essential checkinstall which is needed to build and install the program
            os.chdir('/usr/local/src/') # Changes directory
            subprocess.call(shlex.split('ls'))
            debug('change','dir', '0')
            subprocess.call(shlex.split('sudo wget http://www.noip.com/client/linux/noip-duc-linux.tar.gz')) # Downloading No-IP
            debug('wget','noip', '0')
            subprocess.call(shlex.split('sudo tar xf noip-duc-linux.tar.gz')) 
            debug('tar','noip', '0')
            os.chdir('noip-2.1.9-1/')
            debug('change','dir', '0')
            subprocess.call(shlex.split('sudo checkinstall')) # Installing No-IP
            debug('sudo','checkinstall', '0')
            subprocess.call(shlex.split('sudo chmod 777 /usr/local/etc/no-ip2.conf')) # Sets the no-ip2.conf to read, write, & executable
            debug('chmod', 'no-ip2.conf', '0')
            # Writing startup script
            noipss = open('/home/'+ User +'/noip', 'w')
            noipss.write('#! /bin/sh \n')
            noipss.write('case "$1" in \n')
            noipss.write('  start) \n')
            noipss.write('    echo "Starting noip2" \n')
            noipss.write('    /usr/local/bin/noip2 \n')
            noipss.write('  ;; \n')
            noipss.write('  stop) \n')
            noipss.write('    echo -n "Shutting down noip2" \n')
            noipss.write('    for i in noip2 -S 2>&1 | grep Process | awk \'{print $2}\' | tr -d \',\' \n')
            noipss.write('    do \n')
            noipss.write('      noip2 -K $i \n')
            noipss.write('    done \n')
            noipss.write('  ;; \n')
            noipss.write('  *) \n')
            noipss.write('    echo "Usage: $0 {start|stop}" \n')
            noipss.write('    exit 1 \n')
            noipss.write('esac \n')
            noipss.write('exit 0 \n')
            noipss.close()
            debug('write','noip', '0')
            subprocess.call(shlex.split('sudo mv /home/'+ User +'/noip /etc/init.d/noip'))
            # Testing No-IP and setting permissions
            subprocess.call(shlex.split('sudo chmod 777 /etc/init.d/noip')) # Set Permissions for noip script
            subprocess.call(shlex.split('sudo /etc/init.d/noip stop')) # Stops No-IP
            subprocess.call(shlex.split('sudo /etc/init.d/noip start')) # Start No-IP
            subprocess.call(shlex.split('sudo chmod 700 /usr/local/bin/noip2')) # Set permissions for noip2
            subprocess.call(shlex.split('sudo chown root:root /usr/local/bin/noip2')) # Sets owner to root and group to root for noip2
            subprocess.call(shlex.split('sudo chmod 700 /etc/init.d/noip')) # Sets permissions for noip
            subprocess.call(shlex.split('sudo chown root:root /etc/init.d/noip')) # Sets owner and group to root for noip
            subprocess.call(shlex.split('sudo chmod 700 /usr/local/etc/no-ip2.conf')) # Sets permissions for no-ip2.conf
            subprocess.call(shlex.split('sudo chown root:root /usr/local/etc/no-ip2.conf')) # Sets permissions for no-ip2.conf
            # Adding No-IP to start up script
            subprocess.call(shlex.split('sudo update-rc.d -f noip defaults'))
            os.chdir('/home/'+ User +'/')
    ##########
    # Webmin #
    ##########
    for sel in choice.get_selected_objects():
        if sel == 'Webmin':
            subprocess.call('clear')
            logo()
            print 'Installing Webmin'
            subprocess.call(shlex.split('sudo apt-add-repository "deb http://download.webmin.com/download/repository sarge contrib"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo apt-add-repository "deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo apt-get update'))
            os.chdir('/')
            subprocess.call(shlex.split('sudo wget http://www.webmin.com/jcameron-key.asc')) # Downloading Webmin key
            subprocess.call(shlex.split('sudo apt-key add jcameron-key.asc')) # Adding Webmin key
            subprocess.call(shlex.split('sudo apt-get install -y webmin')) # Installing Webmin
            os.chdir('/home/'+ User +'/')
    ##############
    # PHPMyAdmin #
    ##############
    for sel in choice.get_selected_objects():
        if sel == 'PHPMyAdmin':
            subprocess.call('clear')
            logo()
            print 'Installing PHPMyAdmin'
            subprocess.call(shlex.split('sudo apt-get install -y phpmyadmin')) # Installing PHPMyAdmin
    ########
    # Java #
    ########
    for sel in choice.get_selected_objects():
        if sel == 'Java':
            subprocess.call('clear')
            logo()
            print 'Installing Java'
            subprocess.call(shlex.split('sudo add-apt-repository "ppa:webupd8team/java"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo apt-get update'))
            subprocess.call(shlex.split('sudo apt-get install -y oracle-java7-installer')) # Installing java 7
    ###############
    # Virtual Box #
    ###############
    for sel in choice.get_selected_objects():
        if sel == 'Virtual Box':
            subprocess.call('clear')
            logo()
            print 'Installing Virtual Box'
            subprocess.call(shlex.split('sudo apt-add-repository "deb http://download.virtualbox.org/virtualbox/debian precise contrib"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo wget http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc -O- | sudo apt-key add -')) # Downloading & addng Virtual Box key
            subprocess.call(shlex.split('sudo apt-get update'))
            subprocess.call(shlex.split('sudo apt-get install -y virtualbox-4.2')) # Installing VB
            subprocess.call(shlex.split('sudo apt-get install -y dkms'))
    ##########
    # PHPBB3 #
    ##########
    for sel in choice.get_selected_objects():
        if sel == 'PHPBB3':
            subprocess.call('clear')
            logo()
            print 'Installing PHPBB3 Forums'
            subprocess.call(shlex.split('sudo apt-get install -y phpbb3')) # Installing PHPBB3 forums
    #########
    # Bind9 #
    #########
    for sel in choice.get_selected_objects():
        if sel == 'Bind9'
            subprocess.call('clear')
            logo()
            print 'Installing Bind9'
            subprocess.call(shlex.split('sudo apt-get install -y bind9'))
            dname = raw_output('What is the domain name you want to use? eg. domain.com: ')
			# Writing startup script
            named = open("/home/"+ User +"/named.conf.local", "w")
            named.write('zone "'+ dname +'" {')
            named.write('type master;')
            named.write('file "/etc/bond/zones/'+ dname +'.db";')
            named.wrie('};')
            named.write('')
            named.write('zone "3.2.1.in-addr.arpa" {')
            named.write('type master;')
            named.write('file "/etc/bond/zones/rev.3.2.1.in-addr.arpa";')
            named.write('};')
            named.close()
            debug('write','named.conf.local', 0)
            subprocess.call(shlex.split('sudo mv /home/'+ User +'/named.conf.local /etc/bind/named.conf.local'))
            subprocess.call(shlex.split('sudo mkdir zones'))
            domain = open("/home/"+ User +"/"+ dname +".db", "w")
            domain.write('; BIND data file for '+ dname)
            domain.write(';')
            domain.write('$TTL 14400')
            domain.write('@ IN SOA ns1.'+ dname +'. host.'+ dname +'. (')
            domain.write('201006601 ; Serial')
            domain.write('7200 ; Refresh')
            domain.write('120 ; Retry')
            domain.write('2419200 ; Expire')
            domain.write('604800) ; Default TTL')
            domain.write(';')
            domain.write(dname +'. IN NS ns1.'+ dname +'.')
            domain.write(dname +'. IN NS ns2.'+ dname +'.')
            domain.write('')
            domain.write(dname +'. IN MX 10 mail.'+ dname +'.')
            domain.write(dname +'. IN A '+ IP)
            domain.write('ns1 IN A '+ IP)
            domain.write('ns2 IN A '+ IP)
            domain.write('www IN CNAME '+ dname +'.')
            domain.write('mail IN A '+ IP)
            domain.write('ftp IN CNAME '+ dname +'.')
            domain.write(dname +'. IN TXT "v=spf1 ip4:'+ IP +' a mx ~all"')
            domain.write('mail IN TXT "v=spf1 a -all"')
            domain.close()
            debug('write',dname +'.db', 1)
            subprocess.call(shlex.split('sudo mv /home/'+ User +'/'+ dname +'.db /etc/bind/zones/'+ dname +'.db'))
            rev = open("/home/"+ User +"/rev.3.2.1.in-addr.arpa", "w")
            rev.write('@ IN SOA '+ dname +'. host.'+ dname +'. (')
            rev.write('2020081401;')
            rev.write('28800;')
            rev.write('604800;')
            rev.write('604800;')
            rev.write('86400 );')
            rev.write('IN NS ns1.'+ dname +'.')
            rev.write('4 IN PTR '+ dname +'.')
            rev.close()
            debug('write', 'rev.3.2.1.in-addr.arpa', 1)
            subprocess.call(shlex.split('sudo mv /home/'+ User +'/rev.3.2.1.in-addr.arpa /etc.bind/zones/rev.3.2.1.in-addr.arpa'))
            with open("/etc/resolv.conf") as rev:
                data = rev.readlines()
            data = '["search '+ dname +'"] + '+ data
            for n, line in enumerate(data, 1):
                subprocess.call(shlex.split('sudo echo "'+ data +'" > /etc/resolv.conf'))
            subprocess.call(shlex.split('sudo /etc/init.d/bind9 restart'))
    ##########
    # gitHub #
    ##########
    for sel in choice.get_selected_objects():
        if sel == 'gitHub':
            subprocess.call('clear')
            logo()	
            print 'Installing gitHub'
            dir = os.listdir('/home')
            subprocess.call(shlex.split('sudo apt-get install -y git-core'))
            subprocess.call(shlex.split('sudo apt-get install -y git'))
            local = os.getcwd()
            if local != '/home/'+ User +'/':
			    os.chdir('/home/'+ User +'/')
            git = open('gitHubHelp.txt', 'w')
            git.write('For a list of avalible commands type:')
            git.write('git help -a')
            git.write('')
            git.write('Simple Usage:')
            git.write('git clone <address> <dir> - Clones <address> to <dir>')
            git.write('git add . - Add files/changes to the commit (local)')
            git.write('git commit -a - Bypass add . and automatically generates a message')
            git.write('git commit -m "<message>" - Commit changes and set a message (must use add .)')
            git.write('git push - Push current commit to remote')
            git.write('git pull - Pulls changes off remote branch and update local repository (This may cause issues if the working directory is not clean)')
            git.write('')
            git.write('To clean out the local changes and pull a clean copy of the remote:')				
            git.write('git fetch --all')
            git.write('git reset --hard origin/master')
            git.write('')
            git.write('For the gitHub Cheat Sheet click on the link below')
            git.write('https://github.com/adam-p/markdown-here/wiki/Markdown-Here-Cheatsheet')
            git.close()
            for list in dir:
                if dir != User:
                    subprocess.call(shlex.split('sudo cp gitHubHelp.txt /home/'+ str(dir) +'/'))
    #########
    # UlogD #
    #########
    for sel in choice.get_selected_objects():
        if sel == 'Ulogd':
           subprocess.call('clear')
           logo()	
           print 'Installing UlogD' 
           subprocess.call(shlex.split('sudo apt-get install -y ulogd'))
    ##################
    # Add Admin User #
    ##################
    for sel in choice.get_selected_objects():
        if sel == 'Add Admin':
            subprocess.call('clear')
            logo()
            print 'Adding Admin User'
            AdminUN = raw_input('What username would you like to use?: ')
            AdminPW = raw_input('What password would you like to use for this username?: ')
            subprocess.call(shlex.split('sudo useradd -d /home/'+ AdminUN +' -s /bin/bash -m '+ AdminUN +' -p '+ AdminPW))
            subprocess.call(shlex.split('sudo usermod -L '+ AdminUN))
            subprocess.call(shlex.split('sudo chage -d 0 '+ AdminUN))
            subprocess.call(shlex.split('sudo usermod -U '+ AdminUN))
    ################
    # Finalization #
    ################
    os.chdir('/home/' + User)
    subprocess.call('clear')
    logo()
    print 'Installation is done. There may be a few things you will need to do first. \n\n'
    if sel in choice.get_selected_objects():
        if sel == 'Teamspeak 3':
            print 'Teamspeak 3:'
            print 'You need to start Teamspeak 3 up manually the first time. To do that type: '
            print  'sudo /usr/local/teamspeak3/ts3server_startupscript.sh start \n\n'
        elif sel == 'gitHub':
            print 'gitHub:'
            print 'There has been a help file names \"gitHubHelp.txt\" put in everyone\'s home directory.'
        print ''
        print 'Installation complete'
        print ''
        print 'Installed Programs:'
        if choice.get_selected_objects():
            print(sel)
        if sel == 'TeamSpeak3':
            if arc == '64bit':
                subprocess.call(shlex.split('sudo rm teamspeak-server_linux-amd64-3.0.10.3.tar.gz'))
            elif arc == '32bit':
                subprocess.call(shlex.split('sudo rm teamspeak3-server_linux-x86-3.0.10.3.tar.gz'))
        exit()
        
########################
#
#  Main Script
#
########################
subprocess.call('clear')
logo()
update = raw_input('Before we begin would you like to update the server?: [y]' )
if update == 'y' or update = '':
        subprocess.call(shlex.split('sudo apt-get update'))
        subprocess.call(shlex.split('sudo apt-get upgrade'))
App = InstallApp()
App.run()
if choice.get_selected_objects() is not None:
    install()
else:
    print ''
        
