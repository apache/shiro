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
package org.apache.shiro.samples;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.lang.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * Simple Bean used to demonstrate subject usage.
 */
@Component
public class QuickStart {

    private static Logger log = LoggerFactory.getLogger(QuickStart.class);

    @Autowired
    private SecurityManager securityManager;

    @Autowired
    private SimpleService simpleService;

    public void run() {

        // get the current subject
        Subject subject = SecurityUtils.getSubject();

        // Subject is not authenticated yet
        Assert.isTrue(!subject.isAuthenticated());

        // login the subject with a username / password
        UsernamePasswordToken token = new UsernamePasswordToken("joe.coder", "password");
        subject.login(token);

        // joe.coder has the "user" role
        subject.checkRole("user");

        // joe.coder does NOT have the admin role
        Assert.isTrue(!subject.hasRole("admin"));

        // joe.coder has the "read" permission
        subject.checkPermission("read");

        // current user is allowed to execute this method.
        simpleService.readRestrictedCall();

        try {
            // but not this one!
            simpleService.writeRestrictedCall();
        }
        catch (AuthorizationException e) {
            log.info("Subject was NOT allowed to execute method 'writeRestrictedCall'");
        }

        // logout
        subject.logout();
        Assert.isTrue(!subject.isAuthenticated());
    }


    /**
     * Sets the static instance of SecurityManager. This is NOT needed for web applications.
     */
    @PostConstruct
    private void initStaticSecurityManager() {
        SecurityUtils.setSecurityManager(securityManager);
    }
}
