package com.rnavagamuwa.springsecurity.rest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @author Randika Navagamuwa
 */
@Controller
public class MainController {

    @RequestMapping("/")
    public String root() {

        return "redirect:/index";
    }

    @PreAuthorize("hasPermission('admin_xacml','{action-id:action-id,resource-id:resource-id}')")
    @RequestMapping(path = "/xacml")
    public String test(){

        return "done";
    }

    @PreAuthorize("hasPermission('admin_xacml','{$action-id:action-id,$resource-id:resource-id}')")
    @RequestMapping("/index")
    public String index() {

        return "index";
    }

    @PreAuthorize("hasPermission('admin_xacml','{$action-id:$action-id,$resource-id:resource-id}')")
    @RequestMapping("/user/index")
    public String userIndex() {

        return "user/index";
    }

    @RequestMapping("/login")
    public String login() {

        return "login";
    }

    @RequestMapping("/login-error")
    public String loginError(Model model) {

        model.addAttribute("loginError", true);
        return "login";
    }
}
