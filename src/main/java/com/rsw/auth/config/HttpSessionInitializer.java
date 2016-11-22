package com.rsw.auth.config;

import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;

/**
 * Created by DAlms on 11/20/16.
 */
public class HttpSessionInitializer extends AbstractHttpSessionApplicationInitializer {
    public HttpSessionInitializer() {
        super(HttpSessionConfig.class);
    }
}
