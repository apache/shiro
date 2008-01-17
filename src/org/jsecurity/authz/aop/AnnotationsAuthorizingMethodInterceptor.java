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
package org.jsecurity.authz.aop;

import org.jsecurity.aop.MethodInvocation;
import org.jsecurity.authz.AuthorizationException;

import java.util.ArrayList;
import java.util.Collection;

/**
 * An <tt>AnnotationsAuthorizingMethodInterceptor</tt> is a MethodInterceptor that asserts a given method is authorized
 * to execute based on one or more configured <tt>AuthorizingAnnotationMethodInterceptor</tt>s.
 *
 * <p>This allows multiple annotations on a method to be processed before the method
 * executes, and if any of the <tt>AuthorizingAnnotationMethodInterceptor</tt>s indicate that the method should not be
 * executed, an <tt>AuthorizationException</tt> will be thrown, otherwise the method will be invoked as expected.
 *
 * <p>It is essentially a convenience mechanism to allow multiple annotations to be processed in a single method
 * interceptor.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class AnnotationsAuthorizingMethodInterceptor extends AuthorizingMethodInterceptor {

    protected Collection<AuthorizingAnnotationMethodInterceptor> methodInterceptors = null;

    public void init() {
        super.init();
        if ( methodInterceptors == null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "No methodAuthorizers configured.  " +
                          "Enabling default Role and Permission annotation support..." );
            }
            methodInterceptors = new ArrayList<AuthorizingAnnotationMethodInterceptor>(2);
            methodInterceptors.add( new RoleAnnotationMethodInterceptor( getSecurityManager() ) );
            methodInterceptors.add( new PermissionAnnotationMethodInterceptor( getSecurityManager() ) );
        }

    }

    public Collection<AuthorizingAnnotationMethodInterceptor> getMethodInterceptors() {
        return methodInterceptors;
    }

    public void setMethodInterceptors(Collection<AuthorizingAnnotationMethodInterceptor> methodInterceptors) {
        this.methodInterceptors = methodInterceptors;
    }

    protected void assertAuthorized(MethodInvocation methodInvocation) throws AuthorizationException {
        //default implementation just ensures no deny votes are cast:
        Collection<AuthorizingAnnotationMethodInterceptor> aamis = getMethodInterceptors();
        if ( aamis != null && !aamis.isEmpty() ) {
            for( AuthorizingAnnotationMethodInterceptor aami : aamis ) {
                aami.assertAuthorized( methodInvocation );
            }
        }
    }
}
