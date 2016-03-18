#!/usr/bin/env bash
sleep 10
ldapadd -h openldap -c -D cn=admin,dc=tsers,dc=org -w admin -f /ldif_files/openldap-data.ldif
ldapadd -h openldap-remote -c -D cn=admin,dc=remote,dc=tsers,dc=org -w admin -f /ldif_files/openldap-remote-data.ldif
