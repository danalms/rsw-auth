package com.rsw.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * Created by DAlms on 10/18/16.
 * This protects all endpoints not covered by the ResourceSecurityConfig.
 * By default, all /oauth URIs are protected
 * For example, requests for /oauth/** will invoke a formLogin using default endpoint configurations:
 *   - login page fetch is a GET /login
 *   - login processing is a POST /login
 *
 * The @Order is important here, placing the Web security context lower in the filter chain than the OAuth context
 *
 * CSRF is being disabled for simplicity and demo purposes; normally should not disable CSRF!
 *
 */

@Configuration
@EnableAuthorizationServer
@Order(6)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
                .authorizeRequests()
                    .antMatchers("/login", "/webjars/**").permitAll()
                    .antMatchers("/j_spring_security_check").anonymous()
                    .anyRequest().authenticated()
                .and().formLogin()
                .and().exceptionHandling()
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .and().csrf().disable();
    }

}
