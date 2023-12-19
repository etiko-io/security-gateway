package io.etiko.sg.security;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.etiko.sg.HacProperties;
import reactor.core.publisher.Mono;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

@Component
public class SecurityGlobalFilter implements GlobalFilter, Ordered {

    public static final String ROUTE_METADATA_OAUTH2_CLIENT_REGISTRATION_ID = "hac.security.oauth2.client.registrationId";

    private final HacProperties hacProperties;
    private final WebFilterChainProxy securityChain;

    public SecurityGlobalFilter(final ApplicationContext applicationContext, HacProperties hacProperties) {
        this.hacProperties = hacProperties;
        this.securityChain = newSecurityChainProxy(applicationContext);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (securityChain == null) {
            return chain.filter(exchange);
        }
        final var secProps = hacProperties.getSecurity().getGlobal();
        if (secProps.isOauth2Login() && getRouteOauth2ClientRegistrationId(exchange) == null) {
            final var route = (Route) exchange.getAttribute(GATEWAY_ROUTE_ATTR);
            final var routeId = route == null ? "null" : route.getId();
            throw new IllegalStateException(String.format("Route [%s] has no [%s] metadata value configured",
                    routeId, ROUTE_METADATA_OAUTH2_CLIENT_REGISTRATION_ID));
        }
        return securityChain.filter(exchange, chain::filter);
    }

    private WebFilterChainProxy newSecurityChainProxy(final ApplicationContext applicationContext) {
        if (hacProperties == null || hacProperties.getSecurity() == null
                || hacProperties.getSecurity().getGlobal() == null) {
            return null;
        }

        final var secProps = hacProperties.getSecurity().getGlobal();

        final var requestCache = new WebSessionServerRequestCache();
        final var http = new ApplicationContextAwareServerHttpSecurity(applicationContext);

        if (secProps.isOauth2Login()) {
            http.authorizeExchange((exchange) -> exchange.anyExchange().authenticated())
                    .requestCache(rc -> rc.requestCache(requestCache));
        }

        if (secProps.isOauth2Login()) {
            http
                    .oauth2Login(withDefaults())
                    .oauth2Client(withDefaults()) // TODO: Is this needed?
                    .exceptionHandling(e -> e.authenticationEntryPoint((exchange, ex) -> {
                        if (exchange.getRequest().getHeaders().getAccept().contains(MediaType.APPLICATION_JSON)) {
                            var response = exchange.getResponse();
                            response.setStatusCode(HttpStatus.UNAUTHORIZED);
                            return response.setComplete();
                        }

                        var registrationId = getRouteOauth2ClientRegistrationId(exchange);
                        return requestCache.saveRequest(exchange)
                                .then(new DefaultServerRedirectStrategy().sendRedirect(exchange,
                                        URI.create("/oauth2/authorization/" + registrationId))); // TODO: Make this path
                                                                                                 // configurable
                    }));
        }

        if (secProps.getHeaders().isEnabled()) {
            final var headerProps = secProps.getHeaders();
            final var disabledHeadersCommaSeperated = headerProps.getDisabled();
            final var disabledHeaders = new ArrayList<String>();
            if (disabledHeadersCommaSeperated != null) {
                disabledHeaders.addAll(Arrays.asList(disabledHeadersCommaSeperated.split(",")));
            }

            if (disabledHeaders.contains("frameOptions")) {
                http.headers(h -> h.frameOptions(f -> f.disable()));
            } else {
                http.headers(h -> h.frameOptions(f -> f.mode(headerProps.getFrameOptions())));
            }

            if (disabledHeaders.contains("cache")) {
                http.headers(h -> h.cache(c -> c.disable()));
            }
        } else {
            http.headers(h -> h.disable());
        }

        http
                .csrf(c -> c.disable())
                .logout(l -> l.disable());

        return new WebFilterChainProxy(http.build());
    }

    private String getRouteOauth2ClientRegistrationId(final ServerWebExchange exchange) {
        final var route = (Route) exchange.getAttribute(GATEWAY_ROUTE_ATTR);
        if (route == null) {
            return null;
        }
        return (String) route.getMetadata().get(ROUTE_METADATA_OAUTH2_CLIENT_REGISTRATION_ID);
    }

    private static class ApplicationContextAwareServerHttpSecurity extends ServerHttpSecurity {
        ApplicationContextAwareServerHttpSecurity(final ApplicationContext applicationContext) {
            super();
            setApplicationContext(applicationContext);
        }
    }

}
