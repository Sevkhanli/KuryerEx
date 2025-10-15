package org.example.security;


import lombok.RequiredArgsConstructor;
import org.example.entities.User;
import org.example.enums.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole().name()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override public boolean isAccountNonExpired() { return UserDetails.super.isAccountNonExpired(); }
    @Override public boolean isAccountNonLocked() { return UserDetails.super.isAccountNonLocked(); }
    @Override public boolean isCredentialsNonExpired() { return UserDetails.super.isCredentialsNonExpired(); }
    @Override public boolean isEnabled() { return UserDetails.super.isEnabled(); }

    public Role getRole() {
        return user.getRole();
    }
}