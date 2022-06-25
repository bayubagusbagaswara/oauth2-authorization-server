package com.authorization.server.config;

import com.authorization.server.service.CustomAuthenticationProviderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * class ini digunakan untuk kongfigurasi security secara default pada Authorization Server
 * misalnya semua http request yang masuk harus berhasil terautentikasi dulu
 * dan form login yang digunakan juga default yakni memasukkan username dan password (tampilan login default spring security)
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

    private final CustomAuthenticationProviderService customAuthenticationProvider;

    public DefaultSecurityConfig(CustomAuthenticationProviderService customAuthenticationProvider) {
        this.customAuthenticationProvider = customAuthenticationProvider;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequest -> authorizeRequest
                        .anyRequest()
                        .authenticated())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Autowired
    public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder
                .authenticationProvider(customAuthenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }

}
