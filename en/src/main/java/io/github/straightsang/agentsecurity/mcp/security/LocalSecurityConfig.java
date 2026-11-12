package io.github.straightsang.agentsecurity.mcp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/* Exposes Challenge and approval-preparation APIs without authentication only for local labs; never use in production. */
@Configuration
@Profile("local")
public class LocalSecurityConfig {
    @Bean
    SecurityFilterChain localSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/ping",
                                "/actuator/health",
                                "/identity/challenges",
                                "/approval/prepare",
                                "/mcp",
                                "/mcp/**")
                        .permitAll()
                        .anyRequest().denyAll())
                .build();
    }
}
