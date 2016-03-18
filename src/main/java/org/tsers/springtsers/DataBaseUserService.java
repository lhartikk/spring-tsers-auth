package org.tsers.springtsers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.tsers.springtsers.model.User;
import org.tsers.springtsers.repository.UserRepository;

import java.util.Arrays;

@Component("dataBaseUserService")
@Service
public class DataBaseUserService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        User user = userRepository.findOneByLogin(login).orElseThrow(() -> new UsernameNotFoundException("User not found: " + login));
        return new org.springframework.security.core.userdetails.User(login, user.getPassword(), Arrays.asList());
    }
}
