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
package org.jsecurity.ri.jboss.aop;

import org.jboss.aop.advice.Interceptor;
import org.jboss.aop.joinpoint.Invocation;
import org.jboss.aop.joinpoint.MethodInvocation;
import org.jsecurity.authz.aop.AnnotationsMethodInterceptor;

import java.lang.reflect.Method;

/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class JBossAopAnnotationsMethodInterceptor
        extends AnnotationsMethodInterceptor implements Interceptor {

    private static final String NAME = "JSecurity JBossAopAnnotationsMethodInterceptor";

    public JBossAopAnnotationsMethodInterceptor() {
    }

    public String getName() {
        return NAME;
    }

    protected org.jsecurity.authz.method.MethodInvocation createMethodInvocation(Object implSpecificMethodInvocation) {
        final MethodInvocation mi = (MethodInvocation) implSpecificMethodInvocation;

        return new org.jsecurity.authz.method.MethodInvocation() {
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

    }

    protected Object continueInvocation(Object jbossAopInvocation) throws Throwable {
        Invocation invocation = (Invocation) jbossAopInvocation;
        return invocation.invokeNext();
    }

    public Object invoke(final Invocation invocation) throws Throwable {
        return super.invoke(invocation);
    }

}
