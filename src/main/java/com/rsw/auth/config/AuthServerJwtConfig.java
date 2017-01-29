package com.rsw.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;

/**
 * Created by DAlms on 10/16/16.
 *
 * Minimal configuration to provide JWT tokens to clients upon request, along with a simple token enhancer example
 * Enabling JWT tokens requires extending the AuthServerConfigurerAdapter, which necessitates explicitly providing
 * OAuth client properties.
 */
@Configuration
@ConditionalOnProperty(value = "auth.tokenType", havingValue = "jwt")
public class AuthServerJwtConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${security.oauth2.client.clientId}")
    private String clientId;
    @Value("${security.oauth2.client.clientSecret}")
    private String clientSecret;
    @Value("${auth.security.jwt.signingKey}")
    private String signingKey;
    @Value("${auth.security.jwt.validityDurationSecs}")
    private Integer validityDurationSecs;

    @Autowired
    @Qualifier("rswAuthenticationManager")
    private AuthenticationManager authenticationManager;

    /**
     * The tokenKeyAccess permission (TokenKeyEndpoint) isn't pertinent for oauth2 tokens - only
     * JWTs which may use a protected key for signing (/oauth/token_key endpoint).
     * The checkTokenAccess permission (CheckTokenEndpoint) MAY be pertinent to both oauth2 and Jwt types of tokens,
     * whenever the client wants to validate the token using /oauth/check_token endpoint.
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
     * This is required to instruct the Auth Server to use JWT tokens - by declaring
     * converters and enhancers in this configure() method.
     * The AuthorizationServerEndpointsConfigurer is where the TokenStore is configured.
     *
     * By extending AuthorizationServerConfigurerAdapter, we must explicitly assert other configuration that
     * otherwise can be done via properties for vanilla oauth2 tokens.
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        // order is important: put custom enhancer(s) before JwtAccessTokenConverter, since it does the final encoding
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter()));
        endpoints.tokenStore(tokenStore())
                .authenticationManager(authenticationManager)
                .tokenEnhancer(tokenEnhancerChain);
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        tokenConverter.setSigningKey(signingKey);
        return tokenConverter;
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new JwtTokenEnhancer();
    }

    /**
     *  The authorities defined here are implicitly assigned upon successful auth of the _client_ for a token request.
     *  These authorities are assigned to the OAuth2 _client_, which must provide its own
     *  "authentication" when making token requests.  These authorities are not to be confused with the actual
     *  resource owner's authorities managed by the Spring Security authentication provider whether built-in or custom.
     *  The scope assignment, mapping to roles, etc. can be customized by injecting a custom OAuth2RequestFactory into
     *  the AuthorizationServerEndpointsConfigurer above.  This would override the DefaultOAuth2RequestFactory.
     *  See also the TokenEndpointAuthenticationFilter, as noted in the "Mapping User Roles to Scopes" section of
     *  this doc: https://projects.spring.io/spring-security-oauth/docs/oauth2.html
     *
     *  The resource owner's authorities are revealed by either /oauth/check_access (built into Spring), or via the
     *  endpoint configured for the Spring client.resource.userInfoUri property (which may be a 3rd party endpoint).
     *
     *  Other endpoints configured in the AuthorizationServerSecurityConfigurer.configure() definitions above
     *  can be protected based on the authorities assigned here.
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
                .withClient(clientId)
                .secret(clientSecret)
                .accessTokenValiditySeconds(validityDurationSecs)
                .authorizedGrantTypes("authorization_code","implicit","password","client_credentials","refresh_token")
                .scopes("read", "write")
                .autoApprove("read","write")
                .authorities("ROLE_TRUSTED_CLIENT");
    }
}
