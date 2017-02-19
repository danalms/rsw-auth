package com.rsw.auth.config;

import com.rsw.auth.domain.RswUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by DAlms on 1/1/17.
 * Enhances JWT token claims with RswUser attributes
 */
public class JwtTokenEnhancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        if (authentication.getPrincipal() == null || ! (authentication.getPrincipal() instanceof RswUser)) {
           return accessToken;
        }

        RswUser rswPrincipal = (RswUser) authentication.getPrincipal();
        Map<String, Object> additionalInfo = new HashMap<>();

        additionalInfo.put("username", rswPrincipal.getUsername());
        additionalInfo.put("firstname", rswPrincipal.getFirstName());
        additionalInfo.put("lastname", rswPrincipal.getLastName());
        additionalInfo.put("email", rswPrincipal.getEmailAddress());

        // Setting the "authorities" key here will actually supercede/replace the authorities assigned by
        // the DefaultUserAuthenticationConverter
        //    ... if it's desired to just _add_ an authority to the principal's assigned authorities,
        //        more work would be needed - look at the source for more details
        // additionalInfo.put("authorities", Arrays.asList("ROLE_USER", "ROLE_ADMIN", "ROLE_SA"));

        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

        return accessToken;
    }
}
