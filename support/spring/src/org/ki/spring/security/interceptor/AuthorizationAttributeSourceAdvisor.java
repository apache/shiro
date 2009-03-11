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
package org.ki.spring.security.interceptor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ki.mgt.SecurityManager;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;
import org.springframework.beans.factory.InitializingBean;

import java.lang.reflect.Method;

import org.apache.ki.authz.annotation.RequiresAuthentication;
import org.apache.ki.authz.annotation.RequiresGuest;
import org.apache.ki.authz.annotation.RequiresPermissions;
import org.apache.ki.authz.annotation.RequiresRoles;
import org.apache.ki.authz.annotation.RequiresUser;


/**
 * TODO - complete JavaDoc
 * @author Les Hazlewood
 * @since 0.1
 */
public class AuthorizationAttributeSourceAdvisor extends StaticMethodMatcherPointcutAdvisor
        implements InitializingBean {

    private static final Log log = LogFactory.getLog(AuthorizationAttributeSourceAdvisor.class);

    protected SecurityManager securityManager = null;

    /**
     * Create a new AuthorizationAttributeSourceAdvisor.
     */
    public AuthorizationAttributeSourceAdvisor() {
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(org.apache.ki.mgt.SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /**
     * Returns <tt>true</tt> if the method has any JSecurity annotations, false otherwise.
     * The annotations inspected are:
     * <ul>
     * <li>{@link org.apache.ki.authz.annotation.RequiresAuthentication RequiresAuthentication}</li>
     * <li>{@link org.apache.ki.authz.annotation.RequiresUser RequiresUser}</li>
     * <li>{@link org.apache.ki.authz.annotation.RequiresGuest RequiresGuest}</li>
     * <li>{@link org.apache.ki.authz.annotation.RequiresRoles RequiresRoles}</li>
     * <li>{@link org.apache.ki.authz.annotation.RequiresPermissions RequiresPermissions}</li>
     * </ul>
     *
     * @param method      the method to check for a JSecurity annotation
     * @param targetClass the class potentially declaring JSecurity annotations
     * @return <tt>true</tt> if the method has a JSecurity annotation, false otherwise.
     * @see org.springframework.aop.MethodMatcher#matches(java.lang.reflect.Method, Class)
     */
    public boolean matches(Method method, Class targetClass) {
        return ((method.getAnnotation(RequiresPermissions.class) != null) ||
                (method.getAnnotation(RequiresRoles.class) != null) ||
                (method.getAnnotation(RequiresUser.class) != null) ||
                (method.getAnnotation(RequiresGuest.class) != null ) ||
                (method.getAnnotation(RequiresAuthentication.class) != null ));
    }

    public void afterPropertiesSet() throws Exception {
        if (getAdvice() == null) {
            if (log.isTraceEnabled()) {
                log.trace("No authorization advice explicitly configured via the 'advice' " +
                        "property.  Attempting to set " +
                        "default instance of type [" +
                        AopAllianceAnnotationsAuthorizingMethodInterceptor.class.getName() + "]");
            }
            AopAllianceAnnotationsAuthorizingMethodInterceptor interceptor =
                    new AopAllianceAnnotationsAuthorizingMethodInterceptor();
            setAdvice(interceptor);
        }
    }
}
