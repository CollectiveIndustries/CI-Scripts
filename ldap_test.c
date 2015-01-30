/******************************************************************************************
TITLE: RealmD LDAP Authentication proof of concept

AUTHOR: Andrew Malone (c)

DESCRIPTION:
So far this is a proof of concept for binding to an LDAP directory
as of right now no searching is done very little of this program is usable
all variables are hard-coded into the program

*******************************************************************************************/
#include <stdio.h>
#include <ldap.h>

/*
Variable Definitions
*/

#define LDAP_SERVER "ldaps://127.0.0.1:636"

#define BIND_DN "ou=Internal,dc=collective-industries,dc=net"
#define BASE_DN "dc=collective-industries,dc=net"
#define _SEARCH_STRING_ = "uid=mangos"

/*
start main program
*/

int main( int argc, char **argv )
{
	LDAP    *ld;
	int     rc;
	char    bind_dn[100];
	char	password[] = "k/yHLncYmQOOmJ9B";
	char	username[] = "manager";
	
	/* Get username and password */
	/*if( argc != 3 )
	{
		perror( "invalid args, required: USERNAME PASSWORD\n" );
		return( 1 );
	}*/
	sprintf( bind_dn, "cn=%s,%s", username, BIND_DN);
	printf( "Connecting as: %s\n", bind_dn );
 
	/* Open LDAP Connection */
	if( ldap_initialize( &ld, LDAP_SERVER ) )
	{
		perror( "ldap_initialize" );
		return( 1 );
	}
 
	/* User authentication (bind) */
	rc = ldap_simple_bind_s( ld, bind_dn, password );
	if( rc != LDAP_SUCCESS )
	{
		fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(rc) );
		return( 1 );
	}
	printf( "Successful authentication\n" );
	ldap_unbind( ld );
	return( 0 );
}