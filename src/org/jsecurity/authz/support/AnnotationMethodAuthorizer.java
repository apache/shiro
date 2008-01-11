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
package org.jsecurity.authz.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityManager;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.authz.method.MethodAuthorizer;
import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.util.Initializable;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * Abstract class providing common functionality across methodAuthorizers that process metadata (annotations).
 * Subclass implementations of this operate with a single Annnotation type.  Any arbitrary number of annotations
 * can be supported by subclassing this one and then plugging the implementations in to an
 * {@link org.jsecurity.authz.aop.AnnotationsMethodInterceptor}.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class AnnotationMethodAuthorizer implements MethodAuthorizer, Initializable {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected SecurityManager securityManager;
    protected Class<? extends Annotation> annotationClass;

    public AnnotationMethodAuthorizer() {
    }

    public void init() {
        if ( securityManager == null ) {
            String msg = "SecurityManager property must be set.";
            throw new IllegalStateException( msg );
        }
        if (annotationClass == null) {
            String msg = "annotationClass property must be set";
            throw new IllegalStateException(msg);
        }
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    public void setAnnotationClass(Class<? extends Annotation> annotationClass) {
        this.annotationClass = annotationClass;
    }

    public Class<? extends Annotation> getAnnotationClass() {
        return this.annotationClass;
    }

    protected SecurityContext getSecurityContext() {
        return getSecurityManager().getSecurityContext();
    }

    protected boolean supports(MethodInvocation mi) {
        return getAnnotation( mi ) != null;
    }

    protected Annotation getAnnotation(MethodInvocation mi) {
        if (mi == null) {
            throw new IllegalArgumentException("method argument cannot be null");
        }
        Method m = mi.getMethod();
        if (m == null) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly " +
                    "constructed.  getMethod() returned null";
            throw new IllegalArgumentException(msg);

        }
        return m.getAnnotation(getAnnotationClass());

    }

    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        if ( supports( mi ) ) {
            if ( getSecurityContext() == null ) {
                String msg = "No SecurityContext available to the calling code.  Authorization check " +
                        "cannot occur.";
                throw new UnauthorizedException( msg );
            }
            doAssertAuthorized( mi );
        }
    }

    /**
     * Template hook for subclasses.  When this method is called, the MethodInvocation argument is guaranteed
     * to contain an annotation of type {@link #getAnnotationClass() annotationClass} and a
     * calling SecurityContext will be present (via #getSecurityContext() getSecurityContext()}.
     *
     * @param mi the MethodInvocation to assert authorization
     * @throws AuthorizationException if the caller is not authorized to perform the specified MethodInvocation.
     */
    protected abstract void doAssertAuthorized( MethodInvocation mi ) throws AuthorizationException;
}
