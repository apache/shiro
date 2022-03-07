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

import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.mgt.SecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;
import org.springframework.core.annotation.AnnotationUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;


/**
 * TODO - complete JavaDoc
 *
 * @since 0.1
 */
@SuppressWarnings({"unchecked"})
public class AuthorizationAttributeSourceAdvisor extends StaticMethodMatcherPointcutAdvisor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationAttributeSourceAdvisor.class);

    private static final Class<? extends Annotation>[] AUTHZ_ANNOTATION_CLASSES =
            new Class[] {
                    RequiresPermissions.class, RequiresRoles.class,
                    RequiresUser.class, RequiresGuest.class, RequiresAuthentication.class
            };

    protected SecurityManager securityManager = null;

    /**
     * Create a new AuthorizationAttributeSourceAdvisor.
     */
    public AuthorizationAttributeSourceAdvisor() {
        setAdvice(new AopAllianceAnnotationsAuthorizingMethodInterceptor());
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(org.apache.shiro.mgt.SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /**
     * Returns <tt>true</tt> if the method or the class has any Shiro annotations, false otherwise.
     * The annotations inspected are:
     * <ul>
     * <li>{@link org.apache.shiro.authz.annotation.RequiresAuthentication RequiresAuthentication}</li>
     * <li>{@link org.apache.shiro.authz.annotation.RequiresUser RequiresUser}</li>
     * <li>{@link org.apache.shiro.authz.annotation.RequiresGuest RequiresGuest}</li>
     * <li>{@link org.apache.shiro.authz.annotation.RequiresRoles RequiresRoles}</li>
     * <li>{@link org.apache.shiro.authz.annotation.RequiresPermissions RequiresPermissions}</li>
     * </ul>
     *
     * @param method      the method to check for a Shiro annotation
     * @param targetClass the class potentially declaring Shiro annotations
     * @return <tt>true</tt> if the method has a Shiro annotation, false otherwise.
     * @see org.springframework.aop.MethodMatcher#matches(java.lang.reflect.Method, Class)
     */
    public boolean matches(Method method, Class targetClass) {
        Method m = method;

        if ( isAuthzAnnotationPresent(m) ) {
            return true;
        }

        //The 'method' parameter could be from an interface that doesn't have the annotation.
        //Check to see if the implementation has it.
        if ( targetClass != null) {
            try {
                m = targetClass.getMethod(m.getName(), m.getParameterTypes());
                return isAuthzAnnotationPresent(m) || isAuthzAnnotationPresent(targetClass);
            } catch (NoSuchMethodException ignored) {
                //default return value is false.  If we can't find the method, then obviously
                //there is no annotation, so just use the default return value.
            }
        }

        return false;
    }

    private boolean isAuthzAnnotationPresent(Class<?> targetClazz) {
        for( Class<? extends Annotation> annClass : AUTHZ_ANNOTATION_CLASSES ) {
            Annotation a = AnnotationUtils.findAnnotation(targetClazz, annClass);
            if ( a != null ) {
                return true;
            }
        }
        return false;
    }

    private boolean isAuthzAnnotationPresent(Method method) {
        for( Class<? extends Annotation> annClass : AUTHZ_ANNOTATION_CLASSES ) {
            Annotation a = AnnotationUtils.findAnnotation(method, annClass);
            if ( a != null ) {
                return true;
            }
        }
        return false;
    }

}
