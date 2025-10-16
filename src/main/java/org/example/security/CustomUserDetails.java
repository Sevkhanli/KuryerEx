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

    // 🛑 ƏSAS DÜZƏLİŞ: Hesabın aktiv (təsdiqlənmiş) olub-olmadığını yoxlayır.
    // Bu metod `false` qaytarsa, Spring Security DisabledException atır.
    @Override
    public boolean isEnabled() {
        return user.isVerified();
    }

    // Bu metodları əvvəlki kimi `true` olaraq saxlayırıq (və ya sadələşdiririk)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    public Role getRole() {
        return user.getRole();
    }
}
