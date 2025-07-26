package com.example.security.configuraton;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

import static com.example.security.constants.utils.APP_ROOT;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private  JwtAuthenticationFilter jwtAuthFilter;
    private AuthenticationProvider authenticationProvider;
    private final Environment environment;

    @Autowired
    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthFilter, AuthenticationProvider authenticationProvider, Environment environment){
        this.jwtAuthFilter=jwtAuthFilter;
        this.authenticationProvider=authenticationProvider;
        this.environment = environment;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers(APP_ROOT+"/auth/**","/swagger-ui/**", "/h2-console/**","/v3/api-docs","/**").permitAll()
                                .anyRequest().authenticated()
                )
                .csrf(csrf -> {
                    if (isDevProfile()) {
                        csrf.ignoringRequestMatchers(APP_ROOT+"/auth/**", "/h2-console/**");
                    } else {
                        csrf.ignoringRequestMatchers(APP_ROOT+"auth/**");
                    }
                })
                .headers(headers -> {
                    if (isDevProfile()) {
                        headers
                                .frameOptions(frameOptions -> frameOptions.sameOrigin())
                                .contentTypeOptions(Customizer.withDefaults())
                                .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                                        .maxAgeInSeconds(31536000)
                                        .includeSubDomains(true));
                    } else {
                        headers.frameOptions(frameOptions -> frameOptions.sameOrigin()).disable();
                    }
                })
                .sessionManagement(session->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    private boolean isDevProfile() {
        // Vérifier si on est en développement
        return Arrays.asList(environment.getActiveProfiles()).contains("dev");
    }

}