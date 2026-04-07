package com.school.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for the School API Lambda.
 *
 * JWT validation is handled at the API Gateway level (Cognito JWT Authorizer).
 * Spring Security here only needs to:
 *  1. Permit OPTIONS preflight requests (CORS) without authentication.
 *  2. Allow all other requests through (API Gateway already validated the token).
 *  3. Disable session management (Lambda is stateless).
 *  4. Disable CSRF (stateless REST API).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF — REST API with JWT, no cookies
            .csrf(csrf -> csrf.disable())

            // Stateless — Lambda has no sessions
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Permit OPTIONS (CORS preflight) — all other requests permitted
            // because API Gateway already validated the JWT before reaching Lambda
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().permitAll()
            )

            // No form login, no HTTP basic
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable());

        return http.build();
    }
}
