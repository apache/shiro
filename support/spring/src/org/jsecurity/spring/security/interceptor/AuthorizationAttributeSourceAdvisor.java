/*
 * Copyright (C) 2005-2008 Les Hazlewood
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityManager;
import org.jsecurity.authz.annotation.PermissionsRequired;
import org.jsecurity.authz.annotation.RolesRequired;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;
import org.springframework.beans.factory.InitializingBean;

import java.lang.reflect.Method;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public class AuthorizationAttributeSourceAdvisor extends StaticMethodMatcherPointcutAdvisor
        implements InitializingBean {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SecurityManager securityManager = null;

    /**
     * Create a new AuthorizationAttributeSourceAdvisor.
     */
    public AuthorizationAttributeSourceAdvisor() {
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /**
     * Returns <tt>true</tt> if the method has a JSecurity <tt>RolesRequired</tt> or
     * <tt>PermissionsRequired</tt> annotation, false otherwise.
     * @param method the method to check for a JSecurity annotation
     * @param targetClass the class potentially declaring JSecurity annotations
     * @return <tt>true</tt> if the method has a JSecurity <tt>RolesRequired</tt> or
     * <tt>PermissionsRequired</tt> annotation, false otherwise.
     * @see RolesRequired
     * @see PermissionsRequired
     * @see org.springframework.aop.MethodMatcher#matches(java.lang.reflect.Method, Class)
     */
    public boolean matches( Method method, Class targetClass) {
        return ( (method.getAnnotation( PermissionsRequired.class ) != null ) ||
                 (method.getAnnotation( RolesRequired.class ) != null ) );
    }

    public void afterPropertiesSet() throws Exception {
        if ( getSecurityManager() == null ) {
            String msg = "SecurityManager property must be set";
            throw new IllegalStateException( msg );
        }
        if( getAdvice() == null ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "No authorization advice explicitly configured via the 'advice' " +
                        "property.  Attempting to set " +
                        "default instance of type [" +
                        AopAllianceAnnotationsAuthorizingMethodInterceptor.class.getName() + "]");
            }
            AopAllianceAnnotationsAuthorizingMethodInterceptor interceptor = new AopAllianceAnnotationsAuthorizingMethodInterceptor();
            interceptor.setSecurityManager( getSecurityManager() );
            interceptor.init();

            setAdvice( interceptor );
        }
    }
}
