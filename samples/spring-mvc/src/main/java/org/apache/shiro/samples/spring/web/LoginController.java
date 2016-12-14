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
package org.apache.shiro.samples.spring.web;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Spring MVC controller responsible for authenticating the user.
 *
 * @since 0.1
 */
@Component
@RequestMapping("/s/login")
public class LoginController {

    private static transient final Logger log = LoggerFactory.getLogger(LoginController.class);

    private static String loginView = "login";

    @RequestMapping(method = RequestMethod.GET)
    protected String view() {
        return loginView;
    }

    @RequestMapping(method = RequestMethod.POST)
    protected String onSubmit(@RequestParam("username") String username,
                              @RequestParam("password") String password,
                              Model model) throws Exception {

        UsernamePasswordToken token = new UsernamePasswordToken(username, password);

        try {
            SecurityUtils.getSubject().login(token);
        } catch (AuthenticationException e) {
            log.debug("Error authenticating.", e);
            model.addAttribute("errorInvalidLogin", "The username or password was not correct.");

            return loginView;
        }

        return "redirect:/s/index";
    }
}