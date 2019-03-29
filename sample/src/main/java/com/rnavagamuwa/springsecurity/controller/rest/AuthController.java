package com.rnavagamuwa.springsecurity.controller.rest;

import com.rnavagamuwa.springsecurity.stereotypes.CurrentUser;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class AuthController {

    @RequestMapping("/auth")
    @PreAuthorize("hasPermission('admin_xacml','{actionid:action-id,resourceid:resource-id}')")
    public ResponseEntity sampleAuth(@CurrentUser User user, Model model) {

        return new ResponseEntity<>("Successfully authorized", HttpStatus.OK);
    }
}
