package com.rsw.auth.controller;

import com.rsw.auth.core.RswUserDetailsService;
import com.rsw.auth.domain.RswGroup;
import com.rsw.auth.domain.RswUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Created by DAlms on 11/28/16.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private RswUserDetailsService rswUserService;

    @Autowired
    public AdminController(@Qualifier("rswUserService") RswUserDetailsService rswUserService) {
        this.rswUserService = rswUserService;
    }

    @PreAuthorize("hasRole('ROLE_SYSTEM_ADMIN')")
    @RequestMapping(value = "/user/{username}", method = RequestMethod.GET)
    public RswUser getUser(@PathVariable("username") String userName) {
        return (RswUser) rswUserService.loadUserByUsername(userName);
    }

}
