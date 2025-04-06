package com.ProdeMaster.ApiGateWay.Config;

import io.micrometer.tracing.Tracer;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Hooks;
import reactor.util.context.ContextView;

import brave.handler.SpanHandler;
import brave.sampler.Sampler;
import zipkin2.reporter.AsyncReporter;
import zipkin2.reporter.Reporter;
import zipkin2.reporter.urlconnection.URLConnectionSender;
import zipkin2.reporter.brave.ZipkinSpanHandler;
import zipkin2.Span;

import jakarta.annotation.PostConstruct;

@Configuration
public class TracingConfig {

    @PostConstruct
    public void init() {
        // Habilita automáticamente la restauración del contexto Reactor → MDC
        Hooks.enableAutomaticContextPropagation();
    }

    // Envía spans a Zipkin (localhost:9411 por defecto)
    @Bean
    public Reporter<zipkin2.Span> zipkinReporter() {
        return AsyncReporter.create(URLConnectionSender.create("http://localhost:9411/api/v2/spans"));
    }

    // Handler de Zipkin para enviar los spans
    @Bean
    public SpanHandler zipkinSpanHandler(Reporter<zipkin2.Span> reporter) {
        return ZipkinSpanHandler.create(reporter);
    }

    // Samplear 100% de las peticiones (ideal en desarrollo)
    @Bean
    public Sampler defaultSampler() {
        return Sampler.ALWAYS_SAMPLE;
    }

    // Filtro para propagar el contexto de trazabilidad a MDC en cada request
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
            String spanId = tracer.currentSpan() != null ? tracer.currentSpan().context().spanId() : "";

            MDC.put("traceId", traceId);
            MDC.put("spanId", spanId);
        } catch (Exception ignored) {
        }
    }
}
