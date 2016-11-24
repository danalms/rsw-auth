package com.rsw.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * Created by DAlms on 10/16/16.
 * Minimal configuration to provide OAuth tokens to clients upon request and have the flexibility of
 * more configuration, e.g. grant types, scopes, etc.
 * (most but not all of the oauth2.client properties are actually used internally)
 *
 */
@Configuration
@ConditionalOnProperty(value = "gateway.demo.tokenType", havingValue = "oauth2")
public class AuthServerOAuthConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * this is important: defines access the /oauth/token and check_access endpoints which default to denyAll()
     *   (in this example it's more restrictive and requires an authority)
     * @param oauthServer
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
                .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
                .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
    }

    /**
     * By extending AuthorizationServerConfigurerAdapter, we must explicitly assert configuration that
     * otherwise is the default.
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(new InMemoryTokenStore())
                 .authenticationManager(authenticationManager);
    }

    /**
     *  the authorities defined here are implicitly assigned upon successful auth; these authorities are submitted
     *  to the AuthorizationServerSecurityConfigurer.configure() security definitions above if the matchers are set
     *  up to be restrictive to the authorities.
     *  These are separate from the authorities assigned by the auth manager.
     *  When user/password grant flow is used, the authorities usage may be different (?)
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("rsw")
                .secret("rswsecret")
                .authorizedGrantTypes("authorization_code,client_credentials,refresh_token")
                .scopes("read", "write", "blue")
                .autoApprove("read","write")
                .authorities("ROLE_TRUSTED_CLIENT");
    }

}
