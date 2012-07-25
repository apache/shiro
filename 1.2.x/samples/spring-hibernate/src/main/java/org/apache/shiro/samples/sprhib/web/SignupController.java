/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.samples.sprhib.web;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.samples.sprhib.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Web MVC controller that handles signup requests.
 */
@Controller
public class SignupController {

    private SignupValidator signupValidator = new SignupValidator();

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(value="/signup",method= RequestMethod.GET)
    public String showSignupForm(Model model, @ModelAttribute SignupCommand command) {
        return "signup";
    }

    @RequestMapping(value="/signup",method= RequestMethod.POST)
    public String showSignupForm(Model model, @ModelAttribute SignupCommand command, BindingResult errors) {
        signupValidator.validate(command, errors);

        if( errors.hasErrors() ) {
            return showSignupForm(model, command);
        }

        // Create the user
        userService.createUser( command.getUsername(), command.getEmail(), command.getPassword() );

        // Login the newly created user
        SecurityUtils.getSubject().login(new UsernamePasswordToken(command.getUsername(), command.getPassword()));

        return "redirect:/s/home";
    }

}
