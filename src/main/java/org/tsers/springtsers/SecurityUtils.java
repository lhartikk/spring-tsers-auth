package org.tsers.springtsers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.stereotype.Service;
import org.tsers.springtsers.repository.UserRepository;

import java.util.Arrays;
import java.util.Optional;


@Service
public class SecurityUtils {


    @Autowired
    UserRepository userRepository;

    private SecurityUtils() {

    }

    public User getCurrentUser() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        if (authentication != null) {
            if (authentication.getPrincipal() instanceof org.springframework.security.core.userdetails.User) {
                return (User) authentication.getPrincipal();
            } else if (authentication.getPrincipal() instanceof LdapUserDetailsImpl) {
                String dn = ((LdapUserDetailsImpl) authentication.getPrincipal()).getDn();
                return new User(dn, "", Arrays.asList());
            }
        }
        throw new IllegalStateException("User not found!");
    }
}
