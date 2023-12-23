package io.etiko.sg.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.springframework.core.Ordered;

import io.etiko.sg.SecurityGatewayProperties;
import io.etiko.sg.SecurityGatewayProperties.SecurityRegistrationProperties;

public class SecurityGlobalFilterTest {

    @Test
    public void getOrder_should_return_HIGHEST_PRECEDENCE() {
        final var toTest = new SecurityGlobalFilter(null, null);
        assertEquals(Ordered.HIGHEST_PRECEDENCE, toTest.getOrder());
    }

    @Test
    public void newSecurityChain_Should_return_null_if_Security_Properties_are_not_configured() {
        var toTest = new SecurityGlobalFilter(null, null);
        var actual = toTest.newSecurityChain(null);
        assertNull(actual);

        var sgProperties = new SecurityGatewayProperties();
        toTest = new SecurityGlobalFilter(null, sgProperties);
        actual = toTest.newSecurityChain(null);
        assertNull(actual);

        sgProperties = new SecurityGatewayProperties();
        sgProperties.setSecurity(new SecurityRegistrationProperties());
        toTest = new SecurityGlobalFilter(null, sgProperties);
        actual = toTest.newSecurityChain(null);
        assertNull(actual);
    }

    // @Test
    // public void newSecurityChain_() {
    // var sgProperties = new SecurityGatewayProperties();
    // var secRegProperties = new SecurityRegistrationProperties();
    // var secGlobalProperties = new SecurityProperties();
    // secGlobalProperties.setOauth2Login(true);

    // secRegProperties.setGlobal(secGlobalProperties);
    // sgProperties.setSecurity(secRegProperties);

    // var toTest = new SecurityGlobalFilter(null, sgProperties);

    // var actual = toTest.newSecurityChain(null);

    // }
}
