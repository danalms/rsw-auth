package com.rsw.auth.config;

import com.rsw.auth.domain.RswUser;
import org.assertj.core.util.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;


/**
 * To be used in conjunction with Integration Tests that exercise services with method level security.
 * Those test methods should be annotated with @WithMockCustomUser.
 * Created by DAlms on 12/7/15.
 */
public class WithMockCustomUserSecurityContextFactory implements WithSecurityContextFactory<WithMockCustomUser> {

    @Autowired
    protected JdbcTemplate testJdbcTemplate;

	@Override
	public SecurityContext createSecurityContext(WithMockCustomUser customUser) {
		SecurityContext context = SecurityContextHolder.createEmptyContext();

		GrantedAuthority authority = new SimpleGrantedAuthority(customUser.group().toString());
        RswUser principal = new RswUser(customUser.userName(), "password", true, null, false,
                Lists.newArrayList(authority));

        principal.setFirstName("Test").setLastName("User").setEmailAddress("testuser@example.com");

		Authentication auth = new UsernamePasswordAuthenticationToken(principal, "password", principal.getAuthorities());
		context.setAuthentication(auth);
		return context;
	}

}
