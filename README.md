CI-Scripts
==========

Place for all of Collective Industries Custom scripts that have to do not fit in the other topics

Scripts:
1. ciinstall.py - A python script that allows you to choose which progam(s) you would like to install. Many to choose from and more to add. Once you hit OK on the menu very little else you will need to do
2. exip - short python script to grab your External IP address from dydns and display it thankyou hammerzaine for the function (also used in ciinstall for noip)

Other Programs:
+ The mangos/ldap_test.c program when compiled ( gcc ldap_test.c -o ldapClient -lldap ) is a little proof of concept for an authentication system for MaNGOS wow servers most of the development on this program will be carried out on ClearOS Community Release 6.6.0 Final (CentOS 6 Roots)

Features:
---------
In the obj dir is a set of bashrc scripts that need to be placed in the home directory this will change the bash prompt to display HH:MM $USER_NAME $CWD @ $HOST_NAME ( GIT BRANCH NAME )
time is displayed in green users in blue directory in yellow HostName in Cyan and IF a git repository is found the CURRENT branch is Magenta
never Git Lost again
