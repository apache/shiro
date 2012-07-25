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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.IniConfiguration;
import org.apache.shiro.subject.Subject;

/**
 * @since Aug 28, 2008 5:46:16 PM
 */
public class Standalone {

    public static void main(String[] args) {

        IniConfiguration config = new IniConfiguration();
        //the following call will automatically use shiro.ini at the root of the classpath:
        config.init();

        //This is for Standalone (single-VM) applications that don't use a configuration container (Spring, JBoss, etc)
        //See its JavaDoc for our feelings on this.
        SecurityUtils.setSecurityManager(config.getSecurityManager());

        //Now you are ready to access the Subject, as shown in the Quickstart:
        Subject currentUser = SecurityUtils.getSubject();

        //anything else you want to do with the Subject (see the Quickstart for examples).

        currentUser.logout();

        System.exit(0);
    }
}
