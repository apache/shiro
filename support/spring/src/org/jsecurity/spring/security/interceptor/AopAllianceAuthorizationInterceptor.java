/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.aop.AbstractAuthorizationInterceptor;

import java.lang.reflect.Method;

/**
 * @since 0.2
 * @author Les Hazlewood
 */
public class AopAllianceAuthorizationInterceptor
        extends AbstractAuthorizationInterceptor implements MethodInterceptor {

    protected AuthorizedAction createAuthzAction(final Object aopAllianceMethodInvocation) {
        final MethodInvocation mi = (MethodInvocation) aopAllianceMethodInvocation;

        org.jsecurity.authz.method.MethodInvocation jsecurityMI =
                new org.jsecurity.authz.method.MethodInvocation() {
                    public Method getMethod() {
                        return mi.getMethod();
                    }

                    public Object[] getArguments() {
                        return mi.getArguments();
                    }

                    public String toString() {
                        return "Method invocation [" + mi.getMethod() + "]";
                    }
                };

        return jsecurityMI;
    }

    protected Object continueInvocation( Object aopAllianceMethodInvocation ) throws Throwable {
        MethodInvocation mi = (MethodInvocation)aopAllianceMethodInvocation;
        return mi.proceed();
    }

    public Object invoke( MethodInvocation methodInvocation ) throws Throwable {
        return super.invoke(methodInvocation);
    }
}
