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
 *
 * Example of Java configuration to provide more flexibility for configuring the Auth Server capabilities and
 * security.
 * Note that the oauth2.client properties set in the application.yml do take effect without this class, so
 * for simpler implementations, this class may not be necessary.
 *
 */
@Configuration
@ConditionalOnProperty(value = "gateway.demo.tokenType", havingValue = "oauth2")
public class AuthServerOAuthConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * The tokenKeyAccess permission (TokenKeyEndpoint) probably isn't pertinent for oauth2 tokens - only
     * JWTs which use a protected key for signing.  This is the /oauth/token_key endpoint.
     * The checkTokenAccess permission (CheckTokenEndpoint) MAY be pertinent to both oauth2 and Jwt types of tokens,
     * whenever the client wants to validate the token using /oauth/check_token endpoint.
     *
     * @param oauthServer
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
//        oauthServer
//                .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
//                .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
    }

    /**
     * By extending AuthorizationServerConfigurerAdapter, we must explicitly assert configuration that
     * otherwise is left to default.
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
     *  Note that the authorities defined here are implicitly assigned upon successful auth for the grant
     *  (and for the client_credentials direct token request)
     *  In the AuthorizationServerSecurityConfigurer.configure() security definitions above, if you so wish,
     *  those endpoints can be protected based on the authorities assigned here.
     *  Question: How do these authorities line up with the authorities assigned by a real UserDetails provider?
     *  i.e. when real authentication and assigned authorities are in play?
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("rsw")
                .secret("rswsecret")
                .authorizedGrantTypes("authorization_code","implicit","client_credentials","refresh_token")
                .scopes("read", "write")
                .autoApprove("read","write")
                .authorities("ROLE_USER", "ROLE_DUMMY", "ROLE_TRUSTED_CLIENT");
    }

}
