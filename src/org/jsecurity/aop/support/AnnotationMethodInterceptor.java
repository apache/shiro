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
package org.jsecurity.aop.support;

import org.jsecurity.aop.MethodInvocation;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * MethodInterceptor that inspects a specific annotation on the method invocation before continuing
 * its execution.
 * 
 * @since 1.0
 * @author Les Hazlewood
 */
public abstract class AnnotationMethodInterceptor extends MethodInterceptorSupport {

    protected Class<? extends Annotation> annotationClass;

    public void init() {
        super.init();
        if (annotationClass == null) {
            String msg = "annotationClass property must be set";
            throw new IllegalStateException(msg);
        }
    }

    public void setAnnotationClass(Class<? extends Annotation> annotationClass) {
        this.annotationClass = annotationClass;
    }

    public Class<? extends Annotation> getAnnotationClass() {
        return this.annotationClass;
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

}
