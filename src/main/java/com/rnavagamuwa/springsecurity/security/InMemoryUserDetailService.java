package com.rnavagamuwa.springsecurity.security;

import com.rnavagamuwa.springsecurity.model.CustomUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;

/**
 * @author Randika Navagamuwa
 */
@Component
public class InMemoryUserDetailService implements UserDetailsService {

    private Map<String, CustomUser> users;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public InMemoryUserDetailService(BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostConstruct
    private void init() {

        this.users = new HashMap<>();
        users.put("admin", new CustomUser("admin", bCryptPasswordEncoder.encode("password"),
                new ArrayList<>()));
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        return this.users.get(userName);
    }
}
