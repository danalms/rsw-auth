package com.rsw.auth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;

/**
 * Created by DAlms on 10/22/16.
 *
 * Provides a user details endpoint for Resource Servers that want to get details for the user that a token
 * was issued on behalf of.  Spring Resource Servers would use the Spring client.resource.userInfoUri property,
 * which could also reference a 3rd party resource server.
 *
 */
@RestController
public class UserController {

    /**
     * Hard-coded authorities in this example. for a real implementation, this should consult the security context that
     * will be initialized based on the token provided
     * Note the overlap/duplication between this and the built-in /oauth/check_access endpoint Spring provides
     * (which also provides user details).
     *
     * @param principal
     * @return
     */
    @RequestMapping(value = {"/accountdetails"}, method = RequestMethod.GET)
    public Map<String, Object> getUser(Principal principal) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        map.put("authorities", Arrays.asList("ROLE_USER", "ROLE_ADMIN", "ROLE_SA"));
        return map;
    }

}
