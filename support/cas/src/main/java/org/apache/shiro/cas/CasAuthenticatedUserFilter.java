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
package org.apache.shiro.cas;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * This filter checks if the user is authenticated (not remembered) and sends him to an (updated) CAS login url (if he's already
 * remembered).
 * 
 * @author Jerome Leleu
 * @since 1.3.0
 */
public class CasAuthenticatedUserFilter extends AuthenticationFilter {
    
    public String getLoginUrl() {
        String loginUrl = super.getLoginUrl();
        Subject currentUser = SecurityUtils.getSubject();
        // if user is remembered, add the renew=true parameter to force CAS server to re-authenticate the user
        if (currentUser.isRemembered()) {
            loginUrl += "&renew=true";
        }
        return loginUrl;
    }
    
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        saveRequestAndRedirectToLogin(request, response);
        return false;
    }
}
