package com.rsw.auth.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

/**
 * Created by DAlms on 10/22/16.
 * Protect ResourceServer resources: accountdetails
 * By default, all /oauth URIs are protected
 * All other resources are protected by the Web security configuration
 *
 * Note that this is really only pertinent for OAuth2 (non-JWT) tokens, where clients invoke the
 * URL configured by security.oauth2.resource.userInfoUri to get user details corresponding to an authenticated token
 * Only in that scenario does the Auth Server need to provide a Resource Server function.
 * (and of course the Resource Server function doesn't _have_ to be in the same server as the Auth Server)
 */
@Configuration
@ConditionalOnProperty(value = "gateway.demo.tokenType", havingValue = "oauth2")
@EnableResourceServer
public class ResourceSecurityConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher("/accountdetails")
            .authorizeRequests().anyRequest().authenticated();
    }

}
