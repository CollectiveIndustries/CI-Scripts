#!/usr/bin/python

##################################################################################
#
# Copyright (C) 2013 Collective Industries code provided by Levi Modl
# Python code for installing all the possible programs we use the most
#
##################################################################################

				## TODO ##
# add ulogd install + config
# add iptables firewall script (set default as SSH on 22 only from localnet)
# add mysql database + user for firewall
# add firewall parser (webfwlog) + config (/etc/webfwlog.conf)

# Import all of our needed function
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
import urllib
import re	

# Global Variables
arch = ''    # Variable for the machines architecture
User = ''    # Variable for getting the user who is running this script
IP = ''      # Variable for gettng external IP of server
choice = ''  # Variable for program choices on menu
		
##############################################################################################################################
#
#
# backport for ubuntu 10 (check_output was introduced in python 2.7)
#
#
##############################################################################################################################
if "check_output" not in dir( subprocess ): # duck punch it in!
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd)
        return output
    subprocess.check_output = f

##########################################
#
# Collective Industries Functions
#
##########################################

## Configuration file writter ##
# file gets written line by line
# allows for modification of each line in a configuration file
#
# TODO: add config section for modifying config files
# PROVIDED BY: Andrew Malone
# COPYRIGHT: Collective Industries (C) 2014
def write_conf(in_file_n,out_file_n):
	"""Open in_file_n and install it to out_file_n back up old one first"""
	subprocess.call(shlex.split("cp "+out_file_n+" "+out_file_n+".bak"))#add .bak to the filename provided
	with open(in_file_n,'r') as infile:#open the file and catch errors as an exception
        	with open(out_file_n,"w") as outfile:
                	for i,line in enumerate(infile):
	                	outfile.write(line)#write file line by line

# Collective Industries Debug
def debug(var, msg, DEBUG):
    if DEBUG == '1':
        print var +' = ' + msg
        raw_input('Hit any key to continue')

# Gets External IP address of the server		
def chkip():
    global IP
    url = "http://checkip.dyndns.org"
    request = urllib.urlopen(url).read()
    theIP = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}", request)
    IP = theIP[0]
		
# Collective Industries Logo
def logo():
	print ""
	print " CCCCC       IIIIIIIII"
	print "CCC CCC         III"
	print "CCC CCC         III"
	print "CCC             III"
	print "CCC     ====    III"
	print "CCC     ====    III"
	print "CCC             III"
	print "CCC CCC         III"
	print "CCC CCC         III"
	print " CCCCC       IIIIIIIII   http://ci-main.no-ip.org/"
	print ""

##########################################
#
# Install Menu
#
##########################################
class InstallApp(npyscreen.NPSApp): # Simple UI Menu class by npyscreen
    def main(self):
        Form = npyscreen.ActionForm(name = "Collective Industries Program Installer",) # Creates the menu		

        ###################################################
        #
        # Programs to add
        #
        ###################################################
        # List of other programs to add
        # Mangos-Enhanced
        # LHC
        # Icinga + configuration
        # Moodle
        # phpLdapAdmin
        # UlogD + configuration of database and iptables
        # ClamAV + daemon
        # Mangos + compile install configuration and daemon
        # MySQL Replication
        # System Backup + cron tab with full script path and automated backup script
        # Beep (sudo apt-get install beep)
        # Beep Melodies
        
        # This creates the options and names 
        choice = Form.add(npyscreen.TitleMultiSelect, max_height =-2, value = [], name="Pick the programs you want to install",
            values = ["Teamspeak 3", "No-IP", "Webmin", "PHPMyAdmin", "Java", "Virtual Box", "PHPBB3", "Bind9", "gitHub", "Beep", "Add Admin"], scroll_exit=True)

			
        def on_cancel(self):
            exit()

        # Form.on_cancel = on_cancel
		
        Form.edit() # This allows the person to edit the menu
            

##########################################
#
# Finalization
#
##########################################
def fin():
    debug('Function', 'fin()',1)
    os.chdir('/home/'+User)
    subprocess.call('clear')
	
    print "Installation is done, there may be a few things you will need to do first. \n\n"
	
    for sel in choice.get_selected_objects():
        if sel == "Teamspeak 3":
            print "Teamspeak 3:"
            print "You need to start Teamspeak 3 up manually the first time. To do that type: "
            print "sudo service teamspeak3 start \n\n"
        elif sel == "gitHub":
            print "gitHub:"
            print "There has been a help file named \"gitHubHelp.txt\" put in everyone's home directory."
	
    print "Installation complete"
    print "Installed Programs:"
    if choice.get_selected_objects() is not None:
        for sel in choice.get_selected_objects():
            print (sel)

    if arc == '64bit':
        subprocess.call(shlex.split('sudo rm teamspeak3-server_linux-amd64-3.0.10.3.tar.gz'))
	
    elif arc == '32bit':
        subprocess.call(shlex.split('sudo rm teamspeak3-server_linux-x86-3.0.10.3.tar.gz'))
	
    exit()			

##########################################
#
# Installation
#
##########################################

# Teamspeak 3
def ts3():
    for sel in choice.get_selected_objects():
        if sel == "Teamspeak 3":
            subprocess.call('clear')
            logo()
            print "Installing Teamspeak3"
            debug('arc', arc, 0)
            if str(arc) == '64bit':
                debug('arc', str(arc), 1)
                subprocess.call(shlex.split('wget http://ftp.4players.de/pub/hosted/ts3/releases/3.0.10.3/teamspeak3-server_linux-amd64-3.0.10.3.tar.gz')) # Downloads 64 bit Teamspeak 3 server 
                subprocess.call(shlex.split('sudo tar xzf teamspeak3-server_linux-amd64-3.0.10.3.tar.gz')) # Un compresses file
                subprocess.call(shlex.split('sudo adduser --disabled-login teamspeak3')) # Creates user with no password
                subprocess.call(shlex.split('sudo mv teamspeak3-server_linux-amd64 /usr/local/teamspeak3')) # Moves the Teamspeak folder to a new location

            elif str(arc) == '32bit':
                debug('arc', str(arc), 1)
                subprocess.call(shlex.split('wget http://ftp.4players.de/pub/hosted/ts3/releases/3.0.10.3/teamspeak3-server_linux-x86-3.0.10.3.tar.gz')) # Downloads 32 bit Teamspeak 3 server
                subprocess.call(shlex.split('sudo tar xzf tamespeak3-server_linux-x86-3.0.10.3.tar.gz')) # Un compresses file
                subprocess.call(shlex.split('sudo adduser --disabled-login teamspeak3')) # Creates user with no password
                subprocess.call(shlex.split('sudo mv teamspeak3-server_linux-x86 /usr/local/teamspeak3')) # Moves the eamspeak folder to a new location
		
            subprocess.call(shlex.split('sudo chown -R teamspeak3 /usr/local/teamspeak3')) # Sets the owner to the teamspeak 3 folder to the user teamspeak3
            subprocess.call(shlex.split('sudo ln -s /usr/local/teamspeak3/ts3server_startupscript.sh /etc/init.d/teamspeak3'))
            subprocess.call(shlex.split('sudo update-rc.d teamspeak3 defaults')) # Adds the Teamspeak 3 server to the startup command
            subprocess.call(shlex.split('sudo service teamspeak3 start')) # Starts the Teamspeak 3 server
		
            # Opens up the ports in iptabels needed for Teamspeak 3
            Firewall = raw_input('Open ports in your firewall for Teamspeak 3?: [y]' )
            if Firewall == 'y' or Firewall == '':
                print "Opening ports"
                subprocess.call(shlex.split('sudo iptables -A INPUT -p udp --dport 9987 -j ACCEPT'))
                subprocess.call(shlex.split('sudo iptables -A INPUT -p udp --sport 9987 -j ACCEPT'))
                print "Port 9987 now open"
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --dport 30033 -j ACCEPT'))
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --sport 30033 -j ACCEPT'))
                print "Port 30033 now open"
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --dport 10011 -j ACCEPT'))
                subprocess.call(shlex.split('sudo iptables -A INPUT -p tcp --sport 10011 -j ACCEPT'))
                print "Port 10011 now open"
                noip()

            elif Firewall == 'n':
                noip()
			
        else:
            noip()

# No-IP
def noip():
    for sel in choice.get_selected_objects():
        if sel == "No-IP":
            subprocess.call('clear')
            logo()
            print "Installing No-IP"
            subprocess.call(shlex.split('sudo apt-get install -y build-essential checkinstall')) # Installs build-essential checkinstall which is needed to build and install the program
            os.chdir('/usr/local/src/') # Changes directory
            subprocess.call(shlex.split('ls'))
            debug('change','dir', 0)
            subprocess.call(shlex.split('sudo wget http://www.noip.com/client/linux/noip-duc-linux.tar.gz')) # Downloading No-IP
            debug('wget','noip')
            subprocess.call(shlex.split('sudo tar xf noip-duc-linux.tar.gz')) 
            debug('tar','noip', 0)
            os.chdir('noip-2.1.9-1/')
            debug('change','dir', 0)
            subprocess.call(shlex.split('sudo checkinstall')) # Installing No-IP
            debug('sudo','checkinstall', 0)
            subprocess.call(shlex.split('sudo chmod 777 /usr/local/etc/no-ip2.conf')) # Sets the no-ip2.conf to read, write, & executable
            debug('chmod', 'no-ip2.conf', 0)
        
            # Wriiting startup script
            noipss = open("/home/"+ User +"/noip", "w")
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
            debug('write','noip', 0)
            subprocess.call(shlex.split('sudo mv /home/'+ User +'/noip /etc/init.d/noip'))
 
            # Testing No-IP and setting permissins
            subprocess.call(shlex.split('sudo chmod 777 /etc/init.d/noip')) # Set Permissions for noip script
            subprocess.call(shlex.split('sudo /etc/init.d/noip stop')) # Stops No-IP
            subprocess.call(shlex.split('sudo /etc/init.d/noip start')) # Start No-IP
            subprocess.call(shlex.split('sudo chmod 700 /usr/local/bin/noip2')) # Set permissions for noip2
            subprocess.call(shlex.split('sudo chown root:root /usr/local/bin/noip2')) # Sets owner to root and group to root for noip2
            subprocess.call(shlex.split('sudo chmod 700 /etc/init.d/noip')) # Sets permissions for noip
            subprocess.call(shlex.split('sudo chown root:root /etc/init.d/noip')) # Sets owner and group to root for noip
            subprocess.call(shlex.split('sudo chmod 700 /usr/local/etc/no-ip2.conf')) # Sets permissions for no-ip2.conf
            subprocess.call(shlex.split('sudo chown root:root /usr/local/etc/no-ip2.conf')) # Sets permissions for no-ip2.conf
			
            # Adding No-IP to startup script
            subprocess.call(shlex.split('sudo update-rc.d -f noip defaults'))
            os.chdir('/home/'+ User +'/')
            webmin()
        
        else:
            webmin()

# Webmin
def webmin():
    for sel in choice.get_selected_objects():
        if sel == "Webmin":
            subprocess.call('clear')
            logo()
            print "Installing Webmin"
            subprocess.call(shlex.split('sudo apt-add-repository "deb http://download.webmin.com/download/repository sarge contrib"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo apt-add-repository "deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo apt-get update'))
            os.chdir('/')
            subprocess.call(shlex.split('sudo wget http://www.webmin.com/jcameron-key.asc')) # Downloading Webmin key
            subprocess.call(shlex.split('sudo apt-key add jcameron-key.asc')) # Adding Webmin key
            subprocess.call(shlex.split('sudo apt-get install -y webmin')) # Installing Webmin
            os.chdir('/home/'+ User +'/')
            phpma()

        else:
            phpma()

# PHPMyAdmin
def phpma():
    for sel in choice.get_selected_objects():
        if sel == "PHPMyAdmin":
            subprocess.call('clear')
            logo()
            print "Installing PHPMyAdmin"
            subprocess.call(shlex.split('sudo apt-get install -y phpmyadmin')) # Installing PHPMyAdmin
            java()

        else:
            java()

# Java
def java():
    for sel in choice.get_selected_objects():
        if sel == "Java":
            subprocess.call('clear')
            logo()
            print "Installing Java"
            subprocess.call(shlex.split('sudo add-apt-repository "ppa:webupd8team/java"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo apt-get update'))
            subprocess.call(shlex.split('sudo apt-get install -y oracle-java7-installer')) # Installing java 7
            vb()
        
        else:
            vb()
        
# Virtual Box
def vb():
    for sel in choice.get_selected_objects():
        if sel == "Virtual Box":
            subprocess.call('clear')
            logo()
            print "Installing Virtual Box"
            subprocess.call(shlex.split('sudo apt-add-repository "deb http://download.virtualbox.org/virtualbox/debian precise contrib"')) # Adding repository to sources.list
            subprocess.call(shlex.split('sudo wget -q http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc -O- | sudo apt-key add -')) # Downloading & addng Virtual Box key
            subprocess.call(shlex.split('sudo apt-get update'))
            subprocess.call(shlex.split('sudo apt-get install -y virtualbox-4.2')) # Installing VB
            subprocess.call(shlex.split('sudo apt-get install -y dkms'))
            phpbb3()

        else:
            phpbb3()

# PHPBB3
def phpbb3():
    for sel in choice.get_selected_objects():
        if sel == "PHPBB3":
            subprocess.call('clear')
            logo()
            print "Installing PHPBB3 Forums"
            subprocess.call(shlex.split('sudo apt-get install -y phpbb3')) # Installing PHPBB3 forums
            bind9()
		
        else:
            bind9()

# Bind9
def bind9():
    for sel in choice.get_selected_objects():
        if sel == "Bind9":
            subprocess.call('clear')
            logo()
			
            print "Installing Bind9"
            subprocess.call(shlex.split('sudo apt-get install -y bind9'))
            dname = raw_output('What is the domain name you want to use? eg. domain.com: ')
			# Wriiting startup script
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
            github()

        else:
            github()
			
# gitHub
def github():
    for sel in choice.get_selected_objects():
        if sel == "gitHub":
            subprocess.call('clear')
            logo()			
            print "Installing gitHub"
            dir = os.listdir('/home/')
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
                    subprocess.call(shlex.split('sudo cp gitHubHelp.txt /home/'+ dir +'/'))
            addadmin()

        else:
           addadmin()
	
# Add Admin User
def addadmin():
    for sel in choice.get_selected_objects():
        if sel == "Add Admin":
            subprocess.call('clear')
            logo()
            AdminUN = raw_input('What username would you like to use?: ')
            AdminPW = raw_input('What password would you like to use for this username?: ')
            subprocess.call(shlex.split('sudo useradd -d /home/'+ AdminUN +' -s /bin/bash -m '+ AdminUN +' -p '+ AdminPW))
            subprocess.call(shlex.split('sudo usermod -L '+ AdminUN))
            subprocess.call(shlex.split('sudo chage -d 0 '+ AdminUN))
            subprocess.call(shlex.split('sudo usermod -U '+ AdminUN))
<<<<<<< HEAD
            mangosinstall()

=======
	    #migrate color scripts from REPO/obj to AdminHome/
>>>>>>> 34df331edbc834a3090d17a72f74341c4d647e37
        else:
            mangosinstall()

# Mangos Installer
def mangosinstall():
    for sel in choice.get_selected_objects():
        if sel == "Mangos":
            githubpkg = subprocess.call(shlex.split('dpkg -s git'))
            gitcorepkg = subprocess.call(shlex.split('dpkg -s git-core'))
            subprocess.call('clear')
            if githubpkg == '0' or gitcorepkg == '0':
                print "You must install gitHub before you can install Mangos"
            
            else:
                subprocess.call(shlex.split('git clone https://github.com/CollectiveIndustries/Mangos_Installer.git'))
                os.chdir('/Mangos_Installer')
                subprocess.call(shlex.split('chmod 777 mangos-ci-install.py'))
                subprocess.call(shlex.split('./mangos-ci-install.py'))
                fin()
        else:
            fin()
			
##########################################
#
# Initial Startup
#
##########################################
global arc
global User 

PyPIP = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" python-pip')) # Checks to see if python PIP is installed
Clint = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" clint')) # Checks to see if clint is installed 
SPC = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" software-properties-common')) # Checks to see if software-properties-common is installed
AF = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" apt-file')) # Checks to see if apt-file is installed
P3 = subprocess.call(shlex.split('dpkg-query -W -f="${Status} \n" python3.3')) # Check to see if python 3.3 is installed
npy = subprocess.call(shlex.split('locate npyscreen-3.2.egg-info'))

debug('platform.arch',str(platform.architecture()[0]),1)

arc = platform.architecture()[0]

subprocess.call('clear')

# Python 3.3 Installation
if P3 == 1:
    subprocess.call(shlex.split('sudo apt-get install -y python-software-properties'))
    subprocess.call(shlex.split('sudo add-apt-repository ppa:fkrull/deadsnakes'))
    subprocess.call(shlex.split('sudo apt-get update'))
    subprocess.call(shlex.split('sudo apt-get install -y python3.3'))

# Python PIP Installation	
if PyPIP == 1:
   subprocess.call(shlex.split('sudo apt-get install -y python-pip'))

# Clint Installation
if Clint == 1:
   subprocess.call(shlex.split('pip install clint'))

# software-properties-common Installation
if SPC == 1:
    subprocess.call(shlex.split('sudo apt-get install -y software-properties-common'))    
	
# apt-file Installation and Update	
if AF == 1:
    subprocess.call(shlex.split('sudo apt-get install -y apt-file && apt-file update'))

# Installing npyscreen before importing npyscreen for menu UI 
if npy == '':
    os.chdir('/opt/')
    subprocess.call(shlex.split('sudo wget https://pypi.python.org/packages/source/n/npyscreen/npyscreen-3.37.tar.gz'))
    subprocess.call(shlex.split('tar xvf npyscreen-3.37.tar.gz'))
    os.chdir('npyscreen-3.2')
    subprocess.call(shlex.split('sudo ./setup.py'))
    subprocess.call(shlex.split('sudo rm npyscreen-3.37.tar.gz'))
	
User = getpass.getuser() # Gets the current username 

subprocess.call('clear')
logo()

update = raw_input('Before we begin would you like to update the server?: [y]' )


    
if update == 'y' or  update == '':
    import npyscreen
    subprocess.call(shlex.split('sudo apt-get update -y'))
    subprocess.call(shlex.split('sudo apt-get upgrade -y'))
    App = InstallApp()
    App.run()
    if choice.get_selected_objects() is not None:
	    ts3()		
    elif choice.get_selected_objects() is None:
        print ""

elif update == 'n':
    import npyscreen
    debug('arc',str(arc), 0)
    App = InstallApp()
    App.run() 
    if choice.get_selected_objects() is not None: 
        ts3()
    elif choice.get_selected_objects() is None:
        print ""
#http://rlworkman.net/howtos/ulogd.html ULOGD - help page