package com.springboot.security3.security;

import com.springboot.security3.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final PasswordEncoder passwordEncoder;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .defaultSuccessUrl("/hello", true);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user =
                User.builder()
                .username("user")
                .password(passwordEncoder.encode("password"))
                .roles(Role.USER.name())
                .build();

        UserDetails admin =
                User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
                .roles(Role.ADMIN.name())
                .build();

        return new InMemoryUserDetailsManager(
                user,
                admin
        );
    }
}
