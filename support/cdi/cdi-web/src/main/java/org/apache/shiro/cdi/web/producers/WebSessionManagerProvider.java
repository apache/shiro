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
package org.apache.shiro.cdi.web.producers;

import org.apache.shiro.cdi.web.ServletContainerSessions;
import org.apache.shiro.cdi.web.Web;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class WebSessionManagerProvider {

    @Web
    @ServletContainerSessions
    @Produces
    protected WebSessionManager servletContainerWebSessionManager(@New ServletContainerSessionManager sessionManager) {
        return sessionManager;
    }

    @Produces
    protected WebSessionManager webSessionManager(@ServletContainerSessions WebSessionManager webSessionManager) {
        return webSessionManager;
    }

}
