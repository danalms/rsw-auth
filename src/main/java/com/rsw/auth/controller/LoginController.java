package com.rsw.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Created by DAlms on 10/22/16.
 * Note that we use an ordinary @Controller here to use Spring MVC views
 */
@Controller
public class LoginController {

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String getLogin() {
        return "/";
    }

}
