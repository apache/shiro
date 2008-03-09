/*
 * Copyright (C) 2005-2008 Allan Ditzel
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

package org.jsecurity.web;

import org.jsecurity.JSecurityException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * <p>Base class for all web interceptors. This class is an adapter for the WebInterceptor interface.</p>
 *
 * @author Allan Ditzel
 * @since 0.9
 */
public abstract class AbstractWebInterceptor extends SecurityWebSupport implements WebInterceptor {

    /**
     * Default implementation 
     *
     * @throws JSecurityException
     */
    public void init() throws JSecurityException { }

    /**
     * Default implemenation of this method. Always returns true. Sub-classes should override this method.
     *
     * @param request
     * @param response
     * @return true - allow the request chain to continue in this default implementation
     * @throws Exception
     */
    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    /**
     * Default implementation of this method. Sub-classes should override this method.
     *
     * @param request
     * @param response
     * @throws Exception
     */
    public void postHandle(ServletRequest request, ServletResponse response) throws Exception { }

    /**
     * Default implementation of this method. Sub-classes should override this method. 
     *
     * @param request
     * @param response
     * @param exception
     * @throws Exception
     */
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception { }
}
