package io.etiko.test.helpers;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public class GlobalFilters {
    @Component
    public static class StatusTeapotFilter implements GlobalFilter, Ordered {

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            final var response = exchange.getResponse();
            response.setStatusCode(HttpStatus.I_AM_A_TEAPOT);
            return response.setComplete();
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE - 2; // Just before the WebsocketRoutingFilter global filter
        }

    }
}
