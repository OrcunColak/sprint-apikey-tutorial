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
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
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
    public SecurityFilterChain filterChainWebApplication(HttpSecurity http) throws Exception {
        final String[] AUTH_WHITE_LIST = {
                "/v3/api-docs/**",
                "/swagger-ui/**",
                "/v2/api-docs/**",
                "/swagger-resources/**",

                // Allow ReflectedXSSDemoController
                "/api/xss/**"
        };

        http.authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
                .requestMatchers("/login").permitAll()
                .requestMatchers(AUTH_WHITE_LIST).permitAll()
                .requestMatchers("/**").authenticated()
                .anyRequest().authenticated()
        );

        http.headers(
                header -> header
                        // ENABLED : Add this header = X-XSS-Protection: 1
                        //If a cross-site scripting attack is detected, the browser will sanitize the page (remove the unsafe parts).

                        // ENABLED_MODE_BLOCK  Add this header = X-XSS-Protection: 1; mode=block
                        // Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected.
                        .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED))

                        // Add this header = Content-Security-Policy = script-src 'self'
                        // It means that the web page allows JavaScript code to be executed only if it originates
                        // from the same origin as the page itself.
                        .contentSecurityPolicy(cs -> cs.policyDirectives("script-src 'self'"))
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
