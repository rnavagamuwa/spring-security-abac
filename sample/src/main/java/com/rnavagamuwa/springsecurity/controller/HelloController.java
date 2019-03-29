package com.rnavagamuwa.springsecurity.controller;

import com.rnavagamuwa.springsecurity.stereotypes.CurrentUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HelloController {

    @RequestMapping("/hello")
    public String helloWorld(@CurrentUser User user, Model model) {

        model.addAttribute("username", user.getUsername());
        return "pages/hello";
    }
}
