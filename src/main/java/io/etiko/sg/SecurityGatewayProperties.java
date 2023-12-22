package io.etiko.sg;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Validated
@Configuration
@ConfigurationProperties("etiko.sg")
@Data
public class SecurityGatewayProperties {

    @Valid
    @NotNull
    private SecurityRegistrationProperties security = new SecurityRegistrationProperties();

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

}
