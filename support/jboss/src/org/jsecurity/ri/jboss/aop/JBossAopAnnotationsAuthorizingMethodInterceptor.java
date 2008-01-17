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
import org.jsecurity.authz.aop.AnnotationsAuthorizingMethodInterceptor;

import java.lang.reflect.Method;

/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class JBossAopAnnotationsAuthorizingMethodInterceptor
        extends AnnotationsAuthorizingMethodInterceptor implements Interceptor {

    private static final String NAME = "JSecurity JBossAopAnnotationsAuthorizingMethodInterceptor";

    public JBossAopAnnotationsAuthorizingMethodInterceptor() {
    }

    public String getName() {
        return NAME;
    }

    protected org.jsecurity.aop.MethodInvocation createMethodInvocation(Object implSpecificMethodInvocation) {
        final MethodInvocation mi = (MethodInvocation) implSpecificMethodInvocation;

        return new org.jsecurity.aop.MethodInvocation() {
            public Method getMethod() {
                return mi.getMethod();
            }

            public Object[] getArguments() {
                return mi.getArguments();
            }

            public String toString() {
                return "Method invocation [" + mi.getMethod() + "]";
            }

            public Object proceed() throws Throwable {
                return mi.invokeNext();
            }
        };

    }

    public Object invoke(final Invocation invocation) throws Throwable {
        org.jsecurity.aop.MethodInvocation mi = createMethodInvocation( invocation );
        return super.invoke(mi);
    }

}
