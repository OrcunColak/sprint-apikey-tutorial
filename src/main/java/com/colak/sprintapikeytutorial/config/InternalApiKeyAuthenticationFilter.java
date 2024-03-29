package com.colak.sprintapikeytutorial.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.Map;

@RequiredArgsConstructor
public class InternalApiKeyAuthenticationFilter implements Filter {

    private final String internalApiKey;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        String apiKey = httpServletRequest.getHeader("x-api-key");

        if (apiKey == null) {
            unauthorized(httpServletResponse);
            return;
        }

        if (!internalApiKey.equals(apiKey)) {
            unauthorized(httpServletResponse);
            return;
        }

        chain.doFilter(request, response);
    }

    private void unauthorized(HttpServletResponse httpServletResponse) throws IOException {
        httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        httpServletResponse.setStatus(401);
        Map<String, Object> response = Map.of("message", "SC_UNAUTHORIZED");
        String responseBody = new ObjectMapper().writeValueAsString(response);
        httpServletResponse.getWriter().write(responseBody);
    }
}
