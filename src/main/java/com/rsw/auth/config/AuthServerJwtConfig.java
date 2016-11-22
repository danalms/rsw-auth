package com.rsw.auth.config;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by DAlms on 10/16/16.
 * Minimal configuration to provide JWT tokens to clients upon request, along with a simple token enhancer example
 *
 * Note that here, the OAuth client settings are explicitly in the Java code, rather than from the
 * security.oauth2.client properties, i.e. the property file settings have no effect here
 */
@Configuration
@ConditionalOnProperty(value = "gateway.demo.tokenType", havingValue = "jwt")
public class AuthServerJwtConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${rsw.security.jwt.signingKey}")
    private String signingKey;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * this is important: defines access the /oauth/token and check_access endpoints which default to denyAll()
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
     * This is currently the only way to instruct Auth Server to use JWT tokens - by declaring
     * converters and enhancers in this configure() method.
     * The AuthorizationServerEndpointsConfigurer is where the TokenStore is created, and defaults to
     * JwtTokenStore if the AccessTokenConverter is an instance of JwtAccessTokenConverter.
     * Alternatively the JwtTokenStore can be explicitly set, but its constructory requires a token enhancer.
     * However we wanted to expose and manipulate the token converter in this example, so chose to do it this way.
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
        // order is important here... since JwtAccessTokenConverter does the actual encoding, easier if that comes last
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter()));
        endpoints
                .authenticationManager(authenticationManager)
                .tokenEnhancer(tokenEnhancerChain);
    }

    /**
     * These settings override the properties set in the application.yml
     *  - really DO need all of these settings in this example
     *  - when using authorization_code and similar (other than user/pw) grants, the authorities defined here
     *    appear to be implicitly assigned upon successful auth; these authorities are submitted to the
     *    AuthorizationServerSecurityConfigurer.configure() security definitions above.  These are (maybe) separate from
     *    the authorities assigned by the auth manager.  When user/password grant flow is used, the authorities
     *    usage may be different (?)
     *  - the secret is required for authorization_code grants (not visible in browser debugging), but must
     *    match the gateway's client secret
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("rsw")
                .authorizedGrantTypes("authorization_code")
                .scopes("read", "write")
                .autoApprove("read","write")
                .authorities("ROLE_TRUSTED_CLIENT")
                .secret("rswsecret");
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        tokenConverter.setSigningKey(signingKey);
        return tokenConverter;
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }

    /**
     * Note that by default, the JWT token is created via
     * JwtAccessTokenConverter.encode() -> tokenConverter.convertAccessToken() (DefaultAccessTokenConverter)
     *      -> userTokenConverter.convertUserAuthentication() (DefaultUserAuthenticationConverter)
     */
    public class CustomTokenEnhancer implements TokenEnhancer {
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            Map<String, Object> additionalInfo = new HashMap<>();
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

            // Setting the "authorities" key here will actually supercede/replace the authorities assigned by
            // the DefaultUserAuthenticationConverter
            //    ... if it's desired to just _add_ an authority to the principal's assigned authorities,
            //        more work would be needed - look at the source for more details
            additionalInfo.put("authorities", Arrays.asList("ROLE_USER", "ROLE_ADMIN", "ROLE_SA"));
            additionalInfo.put("organization", authentication.getName() + randomAlphabetic(4));
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

            return accessToken;
        }
    }

}
