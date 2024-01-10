package com.colak.sprintapikeytutorial.controller.xss;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ReflectedXSSDemoController {

    // http://localhost:8080/api/xss?input=<script>alert(%27Hola%20>:)%27);</script>
    @GetMapping("/xss")
    public String xss(@RequestParam String input) {
        // User-entered data is directly reflected in the server’s response
        return "my data " + input;
    }
}
