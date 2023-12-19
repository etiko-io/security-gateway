package io.etiko.sg;

import java.util.ArrayList;
import java.util.List;

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

import io.etiko.sg.security.authz.OAuth2AttributeGatewayFilterFactory;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Configuration
@SpringBootApplication
@RegisterReflectionForBinding(classes = { OAuth2AttributeGatewayFilterFactory.Config.class })
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Autowired
    private HacProperties hacProperties;

    @Bean
    WebSessionIdResolver webSessionIdResolver() {
        final var resolver = new CookieWebSessionIdResolver();
        resolver.setCookieName(hacProperties.getSession().getCookie().getName());
        resolver.setCookieMaxAge(hacProperties.getSession().getCookie().getMaxAge());
        return resolver;
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return new SecurityWebFilterChain() {
            @Override
            public Mono<Boolean> matches(ServerWebExchange exchange) {
                return Mono.just(false);
            }

            @Override
            public Flux<WebFilter> getWebFilters() {
                return Flux.empty();
            }
        };
    }

    @Bean
    ReactiveClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
        List<ClientRegistration> registrations = new ArrayList<>(
                new OAuth2ClientPropertiesMapper(properties).asClientRegistrations().values());
        if (!registrations.isEmpty()) {
            return new InMemoryReactiveClientRegistrationRepository(registrations);
        } else {
            return (registrationId) -> Mono.empty();
        }
    }

}
