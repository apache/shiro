/*
 * Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.context;

/**
 * <p>Factory interface that should be implemented by implementations of the JSecurity API
 * to retrieve a {@link SecurityContext} object for the current context.</p>
 *
 * <p>The actual implementation of this interface used to retrieve the current
 * {@link SecurityContext} is based on the <code>security.context.factory.class</code> property.</p>
 *
 * @see SecurityContext#getSecurityContextFactory(String, ClassLoader)
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public interface SecurityContextFactory {

    /**
     * Returns a {@link SecurityContext} object that represents the current context
     * and allows users of JSecurity access to the primary service interfaces.
     * @param cl the class loader that should be used when loading resources from
     * the classpath.
     * @return the current security context.
     */
    public SecurityContext getContext( ClassLoader cl );
}