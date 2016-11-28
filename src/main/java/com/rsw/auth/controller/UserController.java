package com.rsw.auth.controller;

import com.rsw.auth.domain.RswUser;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by DAlms on 10/22/16.
 *
 * Provides a user details endpoint for Resource Servers that want to get details associated with an oauth2 token
 * in possession.  Spring Resource Servers would use the Spring client.resource.userInfoUri property,
 * which could also reference a 3rd party resource server.
 *
 */
@RestController
public class UserController {

    /**
     * At a minimum the client/caller will expect a map with a "name" key and an "authorities" key.
     * Other data may be included optionally.
     * This can all be fetched directly from the authenticated UserDetails applied in the security context
     * based on the token that was provided on invocation of this endpoint.
     * Note the overlap between this and the built-in /oauth/check_access endpoint Spring provides
     * (which also provides user details).
     *
     * @param currentUser authenticated principal (method arg resolver provides)
     * @return map of username and authorities
     */
    @RequestMapping(value = {"/user"}, method = RequestMethod.GET)
    public Map<String, Object> getUser(@AuthenticationPrincipal UserDetails currentUser) {

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", currentUser.getUsername());

        List<String> authorities = currentUser.getAuthorities()
                .stream().map(a -> a.getAuthority()).collect(Collectors.toList());
        map.put("authorities", authorities);
        if (currentUser instanceof RswUser) {
            RswUser rswUser = (RswUser) currentUser;
            map.put("fullname", String.format("%s %s", rswUser.getFirstName(), rswUser.getLastName()));
            map.put("email", rswUser.getEmailAddress());
        }
        return map;
    }

}
