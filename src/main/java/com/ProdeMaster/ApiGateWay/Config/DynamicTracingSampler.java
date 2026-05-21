package com.ProdeMaster.ApiGateWay.Config;

import brave.sampler.Sampler;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Role-based dynamic tracing sampler.
 * Adjusts Zipkin trace sampling probability according to the authenticated
 * role,
 * which JwtAuthenticationFilter writes into MDC as "user_role".
 *
 * Rates (overridable in application-prod.properties):
 * ADMIN / SUPER_ADMIN → 100%
 * USER → 10%
 * anonymous / unknown → 5%
 */
@Component
public class DynamicTracingSampler extends Sampler {

    @Value("${tracing.sample.rate.admin:1.0}")
    private double adminSampleRate;

    @Value("${tracing.sample.rate.user:0.1}")
    private double userSampleRate;

    @Value("${tracing.sample.rate.public:0.05}")
    private double publicSampleRate;

    @Override
    public boolean isSampled(long traceId) {
        String role = MDC.get("user_role");
        double rate = resolveRate(role);
        return Math.random() < rate;
    }

    private double resolveRate(String role) {
        if (role == null || role.isBlank()) {
            return publicSampleRate;
        }
        if (role.contains("ADMIN") || role.contains("SUPER_ADMIN")) {
            return adminSampleRate;
        }
        if (role.contains("USER")) {
            return userSampleRate;
        }
        return publicSampleRate;
    }
}
