package org.tsers.springtsers;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    public Object loadUserBySAML(SAMLCredential credential)
            throws UsernameNotFoundException {
        XSAnyImpl uid =
                (XSAnyImpl) credential.getAttributes().stream()
                        .filter(a -> a.getFriendlyName().equals("uid"))
                        .findFirst().
                                orElseThrow(() -> new UsernameNotFoundException("uid not found from assertion"))
                        .getAttributeValues().get(0);

        List<GrantedAuthority> authorities = new ArrayList<>();
        return new User(uid.getTextContent(), "", true, true, true, true, authorities);
    }

}
