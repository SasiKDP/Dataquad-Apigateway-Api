
package io.datquad.ApiGateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CookieToHeaderFilter implements GatewayFilter, Ordered {

    private static final String COOKIE_NAME = "authToken";
    private static final String HEADER_NAME = HttpHeaders.AUTHORIZATION;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(COOKIE_NAME);

        if (cookie != null) {
            String token = cookie.getValue();
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header(HEADER_NAME, "Bearer " + token)
                    .build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -100; // Run early
    }
}
