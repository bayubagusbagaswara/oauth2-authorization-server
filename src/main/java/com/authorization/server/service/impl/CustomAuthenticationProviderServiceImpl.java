package com.authorization.server.service.impl;

import com.authorization.server.service.CustomAuthenticationProviderService;
import com.authorization.server.service.CustomUserDetailsService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class CustomAuthenticationProviderServiceImpl implements CustomAuthenticationProviderService {

    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    public CustomAuthenticationProviderServiceImpl(CustomUserDetailsService customUserDetailsService, PasswordEncoder passwordEncoder) {
        this.customUserDetailsService = customUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // ambil username dan password dari object authentication
        // username dan password ini adalah yang dikirim dari User yang ingin login
        // lalu tugas kita adalah autentikasi username dan email

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // ambil data UserDetails berdasarkan username
        UserDetails user = customUserDetailsService.loadUserByUsername(username);

        // cek password apakah sama dengan password yang sudah disimpan di database
        return checkPassword(user, password);
    }

    private Authentication checkPassword(UserDetails user, String rawPassword) {
        // jika password nya sama, maka kembalikan data username, password, authorities dalam object UsernamePasswordAuthenticationToken
        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities());
        } else {
            throw new BadCredentialsException("Bad Credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
