package com.rsw.auth.config;

import com.rsw.auth.core.PasswordService;
import com.rsw.auth.core.RswUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.sql.DataSource;

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
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(6)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${auth.security.password.pattern}")
    private String passwordPattern;
    @Value("${auth.security.password.expireDays}")
    private Integer passwordExpireDays;
    @Value("${auth.security.password.recycleSpan}")
    private Integer passwordRecycleSpan;

    @Autowired
    private DataSource dataSource;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authBuilder) throws Exception {
        authBuilder.userDetailsService(rswUserService()).passwordEncoder(rswPasswordEncoder());
    }

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

    @Bean(name = "rswAuthenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * TODO: use NamedParameterJdbcTemplate
     * @return
     * @throws Exception
     */
    @Bean(name = "rswJdbcTemplate")
    public JdbcTemplate rswJdbcTemplate() throws Exception {
        return new JdbcTemplate(dataSource);
    }

    @Bean(name = "rswPasswordEncoder")
    PasswordEncoder rswPasswordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    PasswordService passwordService() throws Exception {
        PasswordService passwordService = new PasswordService();
        passwordService.setAuthenticationManager(authenticationManagerBean());
        passwordService.setJdbcTemplate(rswJdbcTemplate());
        passwordService.setPasswordEncoder(rswPasswordEncoder());
        passwordService.setPasswordExpiryDays(passwordExpireDays);
        passwordService.setPasswordRecycleSpan(passwordRecycleSpan);
        passwordService.setPasswordFormatRegEx(passwordPattern);
        return passwordService;
    }

    @Bean
    RswUserDetailsService rswUserService() throws Exception {
        RswUserDetailsService userDetailsService = new RswUserDetailsService();
        userDetailsService.setDataSource(dataSource);
        userDetailsService.setPasswordService(passwordService());
        userDetailsService.setEnableAuthorities(false);
        userDetailsService.setEnableGroups(true);
        return userDetailsService;
    }

}
