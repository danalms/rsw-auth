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
     * The checkTokenAccess permission (CheckTokenEndpoint) IS pertinent to both oauth2 and Jwt types of tokens,
     * if the client wants to validate the token using /oauth/check_token endpoint.
     * The permission for both of these endpoints is denyAll() by default, so must be configured here if needed.
     *
     * @param oauthServer
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
//                .tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
                .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
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
     *  The authorities defined here are implicitly assigned upon successful auth of the _client_ for a token request.
     *  These authorities are assigned to the OAuth2 _client_, which must provide its own
     *  "authentication" when making token requests.  So these authorities are not to be confused with the
     *  actual resource owner's authorities, which are determined by an auth manager, implemented in Spring or elsewhere.
     *  The resource owner's authorities are revealed by either /oauth/check_access (built into Spring), or via the
     *  endpoint configured for the Spring client.resource.userInfoUri property (which may be a 3rd party endpoint).
     *
     *  In the AuthorizationServerSecurityConfigurer.configure() security definitions above, if you so wish,
     *  the endpoints there can be protected based on the authorities assigned here.
     *  Beyond that, it's not clear what other purpose the client authorities serve at least in simple implementations.
     *
     *  Note regarding the refresh_token grant type: it appears Spring only produces a refresh_token for the
     *  authorization_code and password grants.
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("rsw")
                .secret("rswsecret")
                .authorizedGrantTypes("authorization_code","implicit","password", "client_credentials","refresh_token")
                .scopes("read", "write")
                .autoApprove("read","write")
                .authorities("ROLE_USER", "ROLE_DUMMY", "ROLE_TRUSTED_CLIENT");
    }

}
