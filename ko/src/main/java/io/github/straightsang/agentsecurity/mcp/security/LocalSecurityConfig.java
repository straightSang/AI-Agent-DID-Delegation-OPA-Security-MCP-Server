package io.github.straightsang.agentsecurity.mcp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/* 로컬 실습에서만 Challenge, 승인 준비, 감사, Ground Truth 조회 API를 인증 없이 연다. 운영 환경에 사용하면 안 된다. */
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
                                "/approval/draft",
                                "/approval/channel/draft",
                                "/approval.html",
                                "/audit/**",
                                "/ground-truth/**",
                                "/mcp",
                                "/mcp/**")
                        .permitAll()
                        .anyRequest().denyAll())
                .build();
    }
}
