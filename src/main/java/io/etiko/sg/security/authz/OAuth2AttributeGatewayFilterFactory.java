package io.etiko.sg.security.authz;

import java.util.Arrays;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.server.ServerWebExchange;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import reactor.core.publisher.Mono;

@Component
public class OAuth2AttributeGatewayFilterFactory
        extends AbstractGatewayFilterFactory<OAuth2AttributeGatewayFilterFactory.Config> {

    public static final String NAME_KEY = "name";
    public static final String REGEXP_KEY = "regexp";

    public OAuth2AttributeGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList(NAME_KEY, REGEXP_KEY);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
                .switchIfEmpty(Mono.defer(() -> complete(exchange, HttpStatus.UNAUTHORIZED)).then(Mono.empty()))
                .flatMap(ctx -> {
                    final var authn = ctx.getAuthentication();
                    final var principal = authn.getPrincipal();

                    if (!(principal instanceof OAuth2AuthenticatedPrincipal)) {
                        return complete(exchange, HttpStatus.BAD_REQUEST);
                    }

                    final var attributeValue = ((OAuth2AuthenticatedPrincipal) principal).getAttribute(config.name);
                    if (attributeValue == null) {
                        return complete(exchange, HttpStatus.FORBIDDEN);
                    }

                    if (!attributeValue.toString().matches(config.regexp)) {
                        return complete(exchange, HttpStatus.FORBIDDEN);
                    }

                    return chain.filter(exchange);
                });
    }

    private Mono<Void> complete(ServerWebExchange exchange, HttpStatus status) {
        final var response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Data
    @Validated
    public static class Config {
        @NotEmpty
        private String name;
        @NotEmpty
        private String regexp;
    }

}
