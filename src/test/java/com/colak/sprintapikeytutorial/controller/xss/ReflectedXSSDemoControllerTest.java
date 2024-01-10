package com.colak.sprintapikeytutorial.controller.xss;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ReflectedXSSDemoControllerTest {
    @Autowired
    private TestRestTemplate testRestTemplate;

    @Test
    void testXss() {
        ResponseEntity<String> responseEntity = testRestTemplate
                .getForEntity("/api/xss?input=<script>alert(%27Hola%20>:)%27);</script>",
                        String.class);

        String result = responseEntity.getBody();
        // It is the responsibility of the web browser to sanitize the response
        assertEquals("my data <script>alert(%27Hola%20>:)%27);</script>", result);
    }
}
