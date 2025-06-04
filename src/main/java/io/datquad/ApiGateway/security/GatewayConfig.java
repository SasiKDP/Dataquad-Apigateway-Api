package io.datquad.ApiGateway.security;

import io.datquad.ApiGateway.filter.CookieToHeaderFilter;
import io.datquad.ApiGateway.filter.JwtAuthenticationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class GatewayConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public GatewayConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        corsConfig.setAllowedOrigins(Arrays.asList("http://192.168.0.246"));
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfig.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));
        corsConfig.setExposedHeaders(Arrays.asList("Authorization"));
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("user_service_auth", r -> r
                        .path("/users/login", "/users/register", "/users/send-otp", "/users/verify-otp", "/users/update-password")
                        .uri("http://localhost:8084"))
                .route("user_service", r -> r
                        .path("/users/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://localhost:8084"))
                .route("requirements_service", r -> r
                        .path("/requirements/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://localhost:8222"))
                .route("candidates_service", r -> r
                        .path("/candidate/**")
                        .filters(f -> f.filter(new CookieToHeaderFilter())
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://localhost:8086"))
                .build();
    }
}
