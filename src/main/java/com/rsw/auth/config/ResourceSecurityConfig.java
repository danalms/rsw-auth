package com.rsw.auth.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * Created by DAlms on 10/22/16.
 *
 * ResourceServer resources are secured here.  URIs matched here will require an OAuth2 token just as the
 * the API endpoints fronted by the gateway do.
 * The login form and Web security (WebSecurityConfig) is not invoked automatically for these requests.
 * Web security (login form) is invoked only for OAuth2 grant requests and other endpoints matched in the Web
 * security configuration.
 *
 * The /user URI is only pertinent for OAuth2 (non-JWT) tokens, where clients invoke the URL configured by
 * security.oauth2.resource.userInfoUri to get user details corresponding to an authenticated token
 * In this example, this is the only resource being hosted by the auth server (acting as both auth and resource servers)
 * Of course the Resource Server function doesn't _have_ to be in the same server as the Auth Server)
 *
 */
@Configuration
@ConditionalOnProperty(value = "gateway.demo.tokenType", havingValue = "oauth2")
@EnableResourceServer
public class ResourceSecurityConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher("/user")
            .authorizeRequests().anyRequest().authenticated();
    }

}
