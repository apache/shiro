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

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.samples.sprhib.model.User;
import org.apache.shiro.samples.sprhib.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Web MVC controller that handles operations related to managing users, such as editing them and deleting them. 
 */
@Controller
public class ManageUsersController {

    private EditUserValidator editUserValidator = new EditUserValidator();

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping("/manageUsers")
    @RequiresPermissions("user:manage")
    public void manageUsers(Model model) {
        model.addAttribute("users", userService.getAllUsers());
    }

    @RequestMapping(value="/editUser",method= RequestMethod.GET)
    @RequiresPermissions("user:edit")
    public String showEditUserForm(Model model, @RequestParam Long userId, @ModelAttribute EditUserCommand command) {

        User user = userService.getUser( userId );
        command.setUserId(userId);
        command.setUsername(user.getUsername());
        command.setEmail(user.getEmail());
        return "editUser";
    }

    @RequestMapping(value="/editUser",method= RequestMethod.POST)
    @RequiresPermissions("user:edit")
    public String editUser(Model model, @RequestParam Long userId, @ModelAttribute EditUserCommand command, BindingResult errors) {
        editUserValidator.validate( command, errors );

        if( errors.hasErrors() ) {
            return "editUser";
        }

        User user = userService.getUser( userId );
        command.updateUser( user );

        userService.updateUser( user );

        return "redirect:/s/manageUsers";
    }

    @RequestMapping("/deleteUser")
    @RequiresPermissions("user:delete")
    public String deleteUser(@RequestParam Long userId) {
        Assert.isTrue( userId != 1, "Cannot delete admin user" );
        userService.deleteUser( userId );
        return "redirect:/s/manageUsers";
    }

}
