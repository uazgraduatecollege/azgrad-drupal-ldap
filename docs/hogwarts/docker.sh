#!/bin/bash

LDAP_DOMAIN=hogwarts.edu
LDAP_DN=dc=hogwarts,dc=edu
LDIF_FILE=hogwarts.people.ldif
SLAPD=slapd
DOCKER_PORT=9389
DOCKER_NAME=hogwarts_ldap

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
