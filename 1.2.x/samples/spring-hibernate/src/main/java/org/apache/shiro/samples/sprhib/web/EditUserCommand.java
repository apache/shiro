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

import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.samples.sprhib.model.User;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Command binding object for editing a user.
 */
public class EditUserCommand {

    private Long userId;
    private String username;
    private String email;
    private String password;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void updateUser(User user) {
        Assert.isTrue( userId.equals( user.getId() ), "User ID of command must match the user being updated." );
        user.setUsername( getUsername() );
        user.setEmail( getEmail() );
        if( StringUtils.hasText(getPassword()) ) {
            user.setPassword( new Sha256Hash(getPassword()).toHex() );
        }
    }
}
