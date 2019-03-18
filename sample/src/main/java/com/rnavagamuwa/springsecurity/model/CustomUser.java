package com.rnavagamuwa.springsecurity.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * @author Randika Navagamuwa
 */
public class CustomUser extends User {

    public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {

        super(username, password, authorities);
    }
}
