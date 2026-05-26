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
 * Minimal distributed-tracing configuration for Spring Boot 3.x + Micrometer Tracing.
 *
 * <p>What Spring Boot provides automatically (no beans needed here):</p>
 * <ul>
 *   <li>Zipkin {@code Reporter} and span exporter — configured from
 *       {@code management.zipkin.tracing.endpoint} in {@code application.properties}.</li>
 *   <li>Default {@code Sampler} with probability from
 *       {@code management.tracing.sampling.probability}.</li>
 *   <li>{@code Tracer} bean wired to the Brave bridge.</li>
 * </ul>
 *
 * <p>What this class adds:</p>
 * <ul>
 *   <li>Reactor automatic context propagation ({@link Hooks#enableAutomaticContextPropagation()})
 *       so trace/span IDs survive thread-pool hops in the reactive pipeline.</li>
 *   <li>An MDC {@link WebFilter} that copies trace and span IDs into SLF4J's MDC on every
 *       request, making them available in log patterns and to
 *       {@link DynamicTracingSampler}.</li>
 * </ul>
 *
 * @see DynamicTracingSampler
 */
@Configuration
public class TracingConfig {

    /**
     * Enables Reactor's automatic context propagation so that Micrometer trace and span IDs
     * are carried across reactive operator boundaries (e.g. {@code subscribeOn},
     * {@code publishOn}, {@code flatMap} with a scheduler).
     *
     * <p>Without this hook, MDC entries written before a thread-pool hop would be lost,
     * causing incomplete trace IDs in log lines.</p>
     */
    @PostConstruct
    public void init() {
        Hooks.enableAutomaticContextPropagation();
    }

    /**
     * WebFilter that copies the current Micrometer trace and span IDs into SLF4J MDC
     * ({@code traceId}, {@code spanId}) so they appear in structured log output.
     *
     * <p>The filter runs on every request and uses {@code contextWrite} to interact with
     * the Reactor context.  Errors during MDC population are silently swallowed to avoid
     * disrupting the request pipeline.</p>
     *
     * @param tracer the Micrometer {@link Tracer} auto-configured by Spring Boot
     * @return a {@link WebFilter} bean registered for every incoming request
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
