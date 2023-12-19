package io.etiko.sg;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Validated
@Configuration
@ConfigurationProperties("hac")
@Data
public class HacProperties {

    @Valid
    @NotNull
    private SecurityRegistrationProperties security = new SecurityRegistrationProperties();

    @Valid
    @NotNull
    private SessionProperties session = new SessionProperties();

    @Validated
    @Data
    public static class SecurityRegistrationProperties {
        @Valid
        private SecurityProperties global;

        @Validated
        @Data
        public static class SecurityProperties {
            private boolean oauth2Login;
            @Valid
            private HeaderProperties headers = new HeaderProperties();

            @Validated
            @Data
            public static class HeaderProperties {
                private boolean enabled = true;
                /**
                 * Comma separated list of headers to disable, example: "cache, frameOptions".
                 * Valid values: cache; frameOptions
                 */
                private String disabled;

                // TODO: add more header support
                private XFrameOptionsServerHttpHeadersWriter.Mode frameOptions = XFrameOptionsServerHttpHeadersWriter.Mode.DENY;
            }
        }
    }

    @Validated
    @Data
    public static class SessionProperties {
        @Valid
        @NotNull
        private CookieProperties cookie = new CookieProperties();

        @Validated
        @Data
        public static class CookieProperties {
            @NotEmpty
            private String name = "_hac_session";
            @NotNull
            private Duration maxAge = Duration.ofSeconds(-1);
        }
    }
}
