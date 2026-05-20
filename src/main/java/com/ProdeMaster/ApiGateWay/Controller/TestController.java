package com.ProdeMaster.ApiGateWay.Controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Development-only endpoint. Disabled by default via app.endpoints.test.enabled=false.
 * To enable in dev: set app.endpoints.test.enabled=true in application-dev.properties.
 * GET /test without this property set to true → 404 Not Found (bean not registered).
 *
 * Item 2.10: Option C (conditional property).
 */
@RestController
@RequestMapping("/test")
@ConditionalOnProperty(name = "app.endpoints.test.enabled", havingValue = "true", matchIfMissing = false)
public class TestController {

    private static final Logger log = LoggerFactory.getLogger(TestController.class);

    @GetMapping
    public Mono<ResponseEntity<String>> testTrace() {
        log.info("Test endpoint accessed - development use only");
        return Mono.just(ResponseEntity.ok("Test endpoint - development only"));
    }
}
