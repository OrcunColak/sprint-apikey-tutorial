package com.colak.sprintapikeytutorial.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SpringSecurityConfig {

    private final APIAuthenticationErrEntrypoint apiAuthenticationErrEntrypoint;

    @Value("${internal.api-key}")
    private String internalApiKey;

    @Bean
    @Order(1)
    public SecurityFilterChain filterChainPrivate(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/internal/**")
                .addFilterBefore(new InternalApiKeyAuthenticationFilter(internalApiKey), ChannelProcessingFilter.class)
                .exceptionHandling(auth -> auth.authenticationEntryPoint(apiAuthenticationErrEntrypoint))
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain filterChainWebAppication(HttpSecurity http) throws Exception {

        final String[] AUTH_WHITE_LIST = {
                "/v3/api-docs/**",
                "/swagger-ui/**",
                "/v2/api-docs/**",
                "/swagger-resources/**"
        };

        http.authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
                .requestMatchers("/login").permitAll()
                .requestMatchers(AUTH_WHITE_LIST).permitAll()
                .requestMatchers("/**").authenticated()
                .anyRequest().authenticated()
        );

        http.formLogin(formLoginCustomizer -> formLoginCustomizer
                .loginPage("/login").permitAll()
                .loginProcessingUrl("/login")
        );

        http.logout(logoutCustomizer -> logoutCustomizer
                .deleteCookies("JSESSIONID")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        );

        http.csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        return authenticationProvider;
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
