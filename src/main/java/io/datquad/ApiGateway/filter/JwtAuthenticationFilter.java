
package io.datquad.ApiGateway.filter;

import io.datquad.ApiGateway.exceptions.InvalidTokenException;
import io.datquad.ApiGateway.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private static final Set<String> PUBLIC_ENDPOINTS = Set.of(
            "/users/register",
            "/users/login",
            "/users/send-otp",
            "/users/verify-otp",
            "/users/update-password"
    );

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        super(Config.class);
        this.jwtService = jwtService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getPath().toString();

            logger.info("Processing request: {} {}", request.getMethod(), path);

            if (request.getMethod() == HttpMethod.OPTIONS || isPublicEndpoint(path)) {
                logger.info("Allowing public or OPTIONS request: {}", path);
                return chain.filter(exchange);
            }

            String token = extractTokenFromRequest(request);
            logger.debug("Extracted token: {}", token != null ? "[present]" : "[missing]");

            if (!StringUtils.hasText(token)) {
                return onError(exchange, "Missing JWT token.", HttpStatus.UNAUTHORIZED);
            }

            try {
                if (!jwtService.validateToken(token)) {
                    return onError(exchange, "Invalid or expired JWT token.", HttpStatus.UNAUTHORIZED);
                }

                String userEmail = jwtService.extractUsername(token);
                logger.info("Authenticated user from JWT: {}", userEmail);

                // Forward user email to downstream services
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-Auth-User", userEmail)
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (InvalidTokenException e) {
                return onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
            } catch (Exception e) {
                logger.error("Unexpected authentication error: {}", e.getMessage(), e);
                return onError(exchange, "Authentication processing error", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        };
    }

    private boolean isPublicEndpoint(String path) {
        return PUBLIC_ENDPOINTS.stream().anyMatch(path::equalsIgnoreCase);
    }

    private String extractTokenFromRequest(ServerHttpRequest request) {
        // Priority: Cookie -> Header
        String tokenFromCookie = extractTokenFromCookie(request);
        if (StringUtils.hasText(tokenFromCookie)) {
            logger.debug("JWT token found in cookie");
            return tokenFromCookie;
        }

        String tokenFromHeader = extractTokenFromHeader(request);
        if (StringUtils.hasText(tokenFromHeader)) {
            logger.debug("JWT token found in Authorization header");
            return tokenFromHeader;
        }

        logger.debug("No JWT token found in cookie or header");
        return null;
    }

    private String extractTokenFromCookie(ServerHttpRequest request) {
        try {
            List<HttpCookie> cookies = request.getCookies().getOrDefault("authToken", List.of());
            if (!cookies.isEmpty()) {
                String token = cookies.get(0).getValue();
                logger.info("Extracted JWT token from cookie: {}", token);  // <-- Full token logged
                return token;
            } else {
                logger.debug("No authToken cookie found.");
            }
        } catch (Exception e) {
            logger.error("Error parsing token from cookie: {}", e.getMessage());
        }
        return null;
    }

    private String extractTokenFromHeader(ServerHttpRequest request) {
        try {
            return request.getHeaders()
                    .getOrEmpty(HttpHeaders.AUTHORIZATION)
                    .stream()
                    .filter(header -> header.toLowerCase().startsWith("bearer "))
                    .map(header -> header.substring(7))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            logger.error("Error parsing token from Authorization header: {}", e.getMessage());
        }
        return null;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        logger.warn("Authentication failed: {} (Status: {})", message, status);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // ✅ Correct CORS headers — use `.set()` to overwrite instead of `.add()`
        response.getHeaders().set("Access-Control-Allow-Origin", "http://192.168.0.246");
        response.getHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.getHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
        response.getHeaders().set("Access-Control-Allow-Credentials", "true");

        String body = String.format("{\"error\": \"%s\", \"status\": %d, \"timestamp\": \"%s\"}",
                message, status.value(), java.time.Instant.now());

        return response.writeWith(
                Mono.just(response.bufferFactory().wrap(body.getBytes()))
        );
    }

    public static class Config {
        private boolean enableDebugLogging = false;

        public boolean isEnableDebugLogging() {
            return enableDebugLogging;
        }

        public void setEnableDebugLogging(boolean enableDebugLogging) {
            this.enableDebugLogging = enableDebugLogging;
        }
    }
}
