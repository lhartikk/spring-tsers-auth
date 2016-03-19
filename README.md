#Spring Boot authentication with MySQL, OpenLDAP and Shibboleth, Dockerized

Example project setting up the following environment:

![alt tag](https://github.com/lhartikk/spring-tsers-auth/blob/master/spring-tsers-auth.jpg)

This example tries to provide **working out-of-the-box** Spring Boot authentication examples with real (dockerized) databases and IDPs including: MySQL, OpenLDAP and Shibboleth. No inMemoryAuthentication() that you usually see in the examples but real end-to-end authentication workflows!

Setting up the environment:
```
git clone https://github.com/lhartikk/spring-tsers-auth.git && cd spring-tsers-auth
docker-compose up -d
./gradlew bootRun
```


[Original Blogpost](https://medium.com/@lhartikk/spring-boot-authentication-with-mysql-openldap-and-shibboleth-dockerized-be9d195cdc99#.vchnr8euu)


Inspired by:

* https://github.com/vdenotaris/spring-boot-security-saml-sample
* https://github.com/jhipster/generator-jhipster
