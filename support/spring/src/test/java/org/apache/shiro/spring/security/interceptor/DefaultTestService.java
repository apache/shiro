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
package org.apache.shiro.spring.security.interceptor;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;

/**
 * @since 1.1
 */
public class DefaultTestService implements TestService {

    @RequiresGuest
    public void guestImplementation() {
    }

    public void guestInterface() {
    }

    @RequiresUser
    public void userImplementation() {
    }

    public void userInterface() {
    }

    @RequiresAuthentication
    public void authenticatedImplementation() {
    }

    public void authenticatedInterface() {
    }

    @RequiresRoles("test")
    public void roleImplementation() {
    }

    public void roleInterface() {
    }

    @RequiresPermissions("test:execute")
    public void permissionImplementation() {
    }

    public void permissionInterface() {
    }
}
