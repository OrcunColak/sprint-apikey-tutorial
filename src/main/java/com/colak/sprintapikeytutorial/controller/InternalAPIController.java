package com.colak.sprintapikeytutorial.controller;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/internal")
public class InternalAPIController {

    @GetMapping(value = "/health")
    @Operation(summary = "Internal Health Check API Summary", description = "API to test Internal Health Check")
    public ResponseEntity<String> internalHealthCheck(@RequestHeader(name = "x-api-key") String yourHeader) {
        return ResponseEntity.ok("ok");
    }
}
