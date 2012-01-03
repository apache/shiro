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

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;

/**
 * This security manager is specifically dedicated to CAS authentication. Remember me is not managed by RememberMeManager but during context
 * initialization in subject creation.
 */
public class CasRememberMeSecurityManager extends DefaultWebSecurityManager {
    
    /**
     * Construct the security manager for CAS. The manager for remember me is explicitly set to null : no {@code RememberMeManager} is
     * required for CAS.
     */
    public CasRememberMeSecurityManager() {
        setRememberMeManager(null);
    }
    
    /**
     * Creates a {@code Subject} instance for the user represented by the given method arguments. As a CAS authentication, the authenticated
     * flag is computed according to the level of authentication : login/password authentication or remember me mode.
     * 
     * @param token the {@code AuthenticationToken} submitted for the successful authentication.
     * @param info the {@code AuthenticationInfo} of a newly authenticated user.
     * @param existing the existing {@code Subject} instance that initiated the authentication attempt
     * @return the {@code Subject} instance that represents the context and session data for the newly authenticated subject.
     */
    @Override
    protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        SubjectContext context = createSubjectContext();
        // set the authenticated flag of the context to true only if the CAS subject is not in a remember me mode
        if (token != null && token instanceof CasToken) {
            CasToken casToken = (CasToken) token;
            if (casToken.isRememberMe()) {
                context.setAuthenticated(false);
            } else {
                context.setAuthenticated(true);
            }
        }
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
        }
        return createSubject(context);
    }
}
