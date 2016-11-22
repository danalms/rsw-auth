package com.rsw.auth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;

/**
 * Created by DAlms on 10/22/16.
 */
@RestController
public class UserController {

    @RequestMapping(value = {"/accountdetails"}, method = RequestMethod.GET)
    public Map<String, Object> getUser(Principal principal) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
//        map.put("authorities", Arrays.asList("ROLE_USER", "ROLE_ADMIN", "ROLE_SA"));
        map.put("authorities", Arrays.asList("ROLE_USER", "ROLE_ADMIN"));
        return map;
    }

}
