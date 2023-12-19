package io.etiko.sg.security.authz;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import io.etiko.test.helpers.GlobalFilters;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@ActiveProfiles("oauth2attrmatch")
@Import(GlobalFilters.StatusTeapotFilter.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class OAuth2AttributeGatewayFilterFactoryTest {
    @Autowired
    ApplicationContext applicationContext;

    WebTestClient webClient;

    @BeforeEach
    void beforeEach() {
        webClient = WebTestClient
                .bindToApplicationContext(applicationContext)
                .apply(springSecurity())
                .configureClient()
                .build();
    }

    @Test
    @WithMockUser
    void Should_fail_with_BAD_REQUEST_if_not_an_OAuth2_User() {
        webClient
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void Should_fail_with_UNAUTHORIZED_if_SecurityContext_is_empty() {
        webClient
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void Should_fail_with_FORBIDDEN_if_attribute_does_not_exist() {
        webClient
                .mutateWith(mockOAuth2Login())
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void Should_fail_with_FORBIDDEN_if_attributes_dont_match() {
        webClient
                .mutateWith(mockOAuth2Login().attributes(attr -> attr.put("id", "WRONGVALUE")))
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void Should_succeed_with_200_OK_if_attributes_match() {
        webClient
                .mutateWith(mockOAuth2Login().attributes(attr -> {
                    attr.put("id", "5174409");
                    attr.put("isEnabled", "true");
                    attr.put("cell", 123456789);
                }))
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.I_AM_A_TEAPOT);
    }

    @Test
    void Should_fail_with_FORBIDDEN_if_only_one_filter_passes() {
        webClient
                .mutateWith(mockOAuth2Login().attributes(attr -> {
                    attr.put("id", "5174409");
                }))
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void Should_succeed_with_200_OK_if_attributes_match_and_attribute_value_is_an_integer() {
        webClient
                .mutateWith(mockOAuth2Login().attributes(attr -> {
                    attr.put("id", 5174409);
                    attr.put("isEnabled", true);
                    attr.put("cell", "987654321");
                }))
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.I_AM_A_TEAPOT);
    }

    @Test
    void Should_fail_with_FORBIDDEN_if_regex_fails() {
        webClient
                .mutateWith(mockOAuth2Login().attributes(attr -> {
                    attr.put("id", 5174409);
                    attr.put("isEnabled", true);
                    attr.put("cell", "98765432");
                }))
                .get().uri("/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FORBIDDEN);
    }

}
