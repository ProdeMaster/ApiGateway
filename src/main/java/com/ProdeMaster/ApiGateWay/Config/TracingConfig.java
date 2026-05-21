package com.ProdeMaster.ApiGateWay.Config;

import io.micrometer.tracing.Tracer;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Hooks;
import reactor.util.context.ContextView;

import jakarta.annotation.PostConstruct;

/**
 * Tracing configuration.
 *
 * Item 3.7: Zipkin reporter and span handler are now auto-configured by Spring Boot from
 *   management.zipkin.tracing.endpoint (see application.properties / application-prod.properties).
 *   The hardcoded URLConnectionSender bean has been removed.
 *
 * Item 3.2: Sampling is handled by DynamicTracingSampler (@Component), which overrides the
 *   default auto-configured sampler and adjusts rates based on the authenticated role in MDC.
 */
@Configuration
public class TracingConfig {

    @PostConstruct
    public void init() {
        // Enables automatic MDC ↔ Reactor context propagation across thread hops.
        Hooks.enableAutomaticContextPropagation();
    }

    /**
     * Propagates Micrometer trace/span IDs into MDC so they appear in structured log output
     * and are accessible to DynamicTracingSampler.
     */
    @Bean
    public WebFilter mdcWebFilter(Tracer tracer) {
        return (exchange, chain) -> chain.filter(exchange)
                .contextWrite(context -> {
                    putToMdc(context, tracer);
                    return context;
                });
    }

    private void putToMdc(ContextView contextView, Tracer tracer) {
        try {
            String traceId = tracer.currentSpan() != null ? tracer.currentSpan().context().traceId() : "";
            String spanId  = tracer.currentSpan() != null ? tracer.currentSpan().context().spanId()  : "";
            MDC.put("traceId", traceId);
            MDC.put("spanId",  spanId);
        } catch (Exception ignored) {
        }
    }
}
