package io.etiko.sg.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;

import io.etiko.test.helpers.GlobalFilters;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;

@ActiveProfiles("security_global_filter")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import(GlobalFilters.StatusTeapotFilter.class)
public class SecurityGlobalFilterIntegrationTest {

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
    void Should_redirect_to_oauth2_login_endpoint_for_correct_oauth2_client_if_not_JSON_request() {
        final var spec = webClient
                .get().uri("https://localhost/")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FOUND)
                .expectHeader().location("/oauth2/authorization/github-1");
        assertSecurityHeaders(spec);
    }

    @Test
    void Should_redirect_to_oauth2_login_endpoint_for_correct_oauth2_client_if_no_JSON_request() {
        final var spec = webClient
                .get().uri("https://localhost/test")
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.UNAUTHORIZED);
        assertSecurityHeaders(spec);
    }

    @Test
    void Should_redirect_allow_access_to_resource_if_all_security_was_handled_correctly() {
        final var spec = webClient
                .mutateWith(mockOAuth2Login().attributes(attr -> attr.put("login", "test_user")))
                .get().uri("https://localhost/test")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.I_AM_A_TEAPOT);
        assertSecurityHeaders(spec);
    }

    @Test
    void Should_redirect_to_provider_when_requesting_oauth2_login_endpoint() {
        final var spec = webClient
                .get().uri("https://localhost/oauth2/authorization/github-1")
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FOUND);
        final var result = spec.returnResult(String.class);

        final var loc = result.getResponseHeaders().getLocation();
        if (loc == null) {
            throw new NullPointerException("loc");
        }
        assertEquals("https", loc.getScheme());
        assertEquals(null, loc.getUserInfo());
        assertEquals("github.com", loc.getHost());
        assertEquals(-1, loc.getPort());
        assertEquals("/login/oauth/authorize", loc.getPath());
        assertTrue(loc.getQuery().contains("client_id=XXX"));

        assertSecurityHeaders(spec);
    }

    private void assertSecurityHeaders(ResponseSpec spec) {
        spec
                .expectHeader().valueEquals("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                .expectHeader().valueEquals("Pragma", "no-cache")
                .expectHeader().valueEquals("Expires", "0")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains")
                .expectHeader().valueEquals("X-Frame-Options", "SAMEORIGIN")
                .expectHeader().valueEquals("X-XSS-Protection", "0");
    }

}
