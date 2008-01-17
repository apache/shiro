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
package org.jsecurity.aop.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityManager;
import org.jsecurity.aop.MethodInterceptor;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.util.Initializable;

/**
 * This class is an abstraction of AOP method interceptor behavior specific to JSecurity that
 * leaves AOP implementation specifics to be handled by subclass implementations.  Shared behavior
 * is defined in this class.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class MethodInterceptorSupport implements MethodInterceptor, Initializable {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SecurityManager securityManager = null;

    public MethodInterceptorSupport(){}

    public void init() {
        if ( securityManager == null ) {
            throw new IllegalStateException( "SecurityManager property must be set." );
        }
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    protected SecurityContext getSecurityContext() {
        return getSecurityManager().getSecurityContext();
    }
}
