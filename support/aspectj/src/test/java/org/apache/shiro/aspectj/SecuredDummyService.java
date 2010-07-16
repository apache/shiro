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
package org.apache.shiro.aspectj;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;

import java.sql.Timestamp;

/**
 * Secured implementation of te dummy service that requires some permissions to execute.
 *
 */
public class SecuredDummyService implements DummyService {

    @RequiresAuthentication
    @RequiresPermissions("dummy:admin")
    public void change() {
        retrieve();
        log("change");
        peek();
    }

    public void anonymous() {
        log("anonymous");
    }

    @RequiresGuest
    public void guest() {
        log("guest");
    }

    @RequiresUser
    public void peek() {
        log("peek");
    }

    @RequiresPermissions("dummy:user")
    public void retrieve() {
        log("retrieve");
    }

    public void log(String aMessage) {
        if (aMessage != null) {
            System.out.println(new Timestamp(System.currentTimeMillis()).toString() + " [" + Thread.currentThread() + "] * LOG * " + aMessage);
        } else {
            System.out.println("\n\n");
        }
    }

}
