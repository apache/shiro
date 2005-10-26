/*
 * Copyright (C) 2005 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.spring.security.interceptor;

import org.jsecurity.authz.annotation.HasPermission;
import org.jsecurity.authz.annotation.HasRole;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;

import java.lang.reflect.Method;

/**
 * Created on: Oct 24, 2005 2:23:27 PM
 *
 * @author Les Hazlewood
 */
public class AuthorizationAttributeSourceAdvisor extends StaticMethodMatcherPointcutAdvisor {

    /**
     * Create a new AuthorizationAttributeSourceAdvisor.
     */
    public AuthorizationAttributeSourceAdvisor() {
    }

    /**
     * Create a new AuthorizationAttributeSourceAdvisor.
     * @param interceptor the security interceptor to use for this advisor
     */
    public AuthorizationAttributeSourceAdvisor( AuthorizationInterceptor interceptor) {
        setSecurityInterceptor(interceptor);
    }

    /**
     * Set the security interceptor to use for this advisor.
     */
    public void setSecurityInterceptor(AuthorizationInterceptor interceptor) {
        setAdvice(interceptor);
    }

    /**
     * Returns <tt>true</tt> if the method has a JSecurity <tt>HasRole</tt> or
     * <tt>HasPermission</tt> annotation, false otherwise.
     * @param method the method to check for a JSecurity annotation
     * @param targetClass the class potentially declaring JSecurity annotations
     * @return <tt>true</tt> if the method has a JSecurity <tt>HasRole</tt> or
     * <tt>HasPermission</tt> annotation, false otherwise.
     * @see HasRole
     * @see HasPermission
     * @see org.springframework.aop.MethodMatcher#matches(java.lang.reflect.Method, Class)
     */
    public boolean matches( Method method, Class targetClass) {
        return ( (method.getAnnotation( HasPermission.class ) != null ) ||
                 (method.getAnnotation( HasRole.class ) != null ) );
    }

}
