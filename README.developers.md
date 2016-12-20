# Overview of the LDAP suite

The LDAP suite of modules is modular to allow you to pick and choose the elements your use-case requires. The current
structure is not necessarily ideal but rather keeps with the existing framework to avoid additional migration work.

The architecture in Drupal 8 differs significantly from Drupal 7 and will need to evolve further to become better
testable. The currently present (non-working) integration tests relied on a highly complex configuration and setup
based on SimpleTest. The goal of the current branch is to improve test coverage wherever possible through unit tests and
this testing architecture is being phased out step by step.

## Setting up a development environment

To quickly get up and running without using a production system to query against you can make use of Docker. An example
configuration is provided in the docs directory based on the Harry Potter schools.

The following script - based on a script by [Laudanum](https://github.com/Laudanum) - populates a Docker instance as
required (adjust paths where necessary for your *.ldif files):

```bash
#!/bin/bash

LDAP_DOMAIN=example.org
LDAP_DN=dc=example,dc=org
LDIF_FILE=hogwarts.people.ldif
SLAPD=slapd
DOCKER_PORT=9389
DOCKER_NAME=ldap

# Kill previous docker
LDAP_CID=`docker ps --filter "name=${DOCKER_NAME}" --format "{{.ID}}"`
echo LDAP_CID $LDAP_CID
if [ $LDAP_CID ]
	then
		echo "Stopping $DOCKER_NAME $LDAP_CID"
		docker stop $LDAP_CID
		docker rm $LDAP_CID
fi

echo "Starting $DOCKER_NAME"
LDAP_CID=$(docker run -e LDAP_TLS=false -e LDAP_DOMAIN="$LDAP_DOMAIN" -p $DOCKER_PORT:389 --name=$DOCKER_NAME -d osixia/openldap)

if [ -z "$LDAP_CID" ]
	then
	echo "No LDAP CID. Exiting."
	exit
fi

docker cp $LDIF_FILE $LDAP_CID:/$LDIF_FILE
docker cp grants.ldif $LDAP_CID:/grants.ldif

docker exec -it $LDAP_CID ls

DOCKER_IP=127.0.0.1

sleep 3
echo "Importing LDIF"
ldapadd -h $DOCKER_IP -p $DOCKER_PORT -x -D "cn=admin,$LDAP_DN" -w admin -f $LDIF_FILE

echo IP $DOCKER_IP
echo PORT $DOCKER_PORT
echo ID $LDAP_CID

docker exec -it $LDAP_CID ldapmodify -Y EXTERNAL -H ldapi:/// -f /grants.ldif

echo "Searching LDAP"
ldapsearch -x -h $DOCKER_IP -p $DOCKER_PORT -b $LDAP_DN -D "cn=hpotter,ou=people,$LDAP_DN" -w pass
```

## Various LDAP Project Notes

### Case Sensitivity and Character Escaping in LDAP Modules

The class MassageFunctions should be used for dealing with case sensitivity
and character escaping consistently.

The general rule is codified in MassageFunctions which is:
* escape filter values and attribute values when querying ldap
* use unescaped, lower case attribute names when storing attribute names in arrays (as keys or values), databases, or object properties.
* use unescaped, mixed case attribute values when storing attribute values in arrays (as keys or values), databases, or object properties.

So a filter might be built as follows:

```php
$massage = new MassageFunctions;
$username = $massage->massage_text($username, 'attr_value', $massage::$query_ldap)
$objectclass = $massage->massage_text($objectclass, 'attr_value', $massage::$query_ldap)
$filter = "(&(cn=$username)(objectClass=$objectclass))";
```

The following functions are also available:

* escape_dn_value()
* unescape_dn_value()
* unescape_filter_value()
* unescape_filter_value()

### Common variables used in ldap_* and their structures

The structure of $ldap_user and $ldap_entry are different!

#### $ldap_user
@see LdapServer::userUserNameToExistingLdapEntry() return

#### $ldap_entry and $ldap_*_entry.
@see LdapServer::ldap_search() return array

####  $user_attr_key
key of form <attr_type>.<attr_name>[:<instance>] such as field.lname, property.mail, field.aliases:2

## Additional links

* http://www-01.ibm.com/support/docview.wss?uid=swg21240892
* https://cwiki.apache.org/GMOxDOC21/ldap-sample-app-ldap-sample-application.html
* http://trac-hacks.org/wiki/LdapPluginTests
* http://en.wikipedia.org/wiki/Hogwarts
* http://harrypotter.wikia.com/wiki/Hogwarts_School_of_Witchcraft_and_Wizardry