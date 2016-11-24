package com.rsw.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.session.SessionAutoConfiguration;

/**
 * Internal AuthServer implementation example
 *
 * Reference:
 * https://spring.io/guides/tutorials/spring-boot-oauth2/
 *
 * Need to explicitly exclude SessionAutoConfiguration and import it conditionally based on cloud profile
 * Goal is to not use Redis and Spring Session when running locally - use only in cloud profile
 */
@SpringBootApplication(exclude = SessionAutoConfiguration.class)
public class RswAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(RswAuthServerApplication.class, args);
	}
}
