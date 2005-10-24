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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.context.SecurityContext;
import org.springframework.beans.factory.InitializingBean;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Method;

/**
 * Created on: Oct 24, 2005 2:32:29 PM
 *
 * @author Les Hazlewood
 */
public class AuthorizationInterceptor implements InitializingBean, MethodInterceptor {

    protected transient final Log log = LogFactory.getLog( getClass() );

    private Authorizer authorizer;

    public void setAuthorizer( Authorizer authorizer ) {
        this.authorizer = authorizer;
    }

    public void afterPropertiesSet() throws Exception {
        if ( this.authorizer == null ) {
            String msg = "authorizer property must be set";
            throw new IllegalStateException( msg );
        }
    }


    public Object invoke( final MethodInvocation mi ) throws Throwable {

        AuthorizationContext authzCtx = SecurityContext.getAuthorizationContext();

        if ( authzCtx != null ) {
            org.jsecurity.authz.method.MethodInvocation jsecurityMI =
                new org.jsecurity.authz.method.MethodInvocation() {
                    public Method getMethod() {
                        return mi.getMethod();
                    }

                    public Object[] getArguments() {
                        return mi.getArguments();
                    }
                };

            this.authorizer.checkAuthorization( authzCtx, jsecurityMI );
        } else {
            if ( log.isWarnEnabled() ) {
                log.warn( "No AuthorizationContext available via " +
                SecurityContext.class.getName() + ".getAuthorizationContext().  Authorization" +
                "check will not be executed.");
            }
        }

        return mi.proceed();
    }

}
