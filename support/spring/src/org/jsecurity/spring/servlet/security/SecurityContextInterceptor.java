/*
 * Copyright (C) 2005 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.spring.servlet.security;

import org.jsecurity.web.support.SecurityContextWebInterceptor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interceptor that is used to ensure an {@link org.jsecurity.context.SecurityContext} is bound to the
 * thread local on every request, if it exists.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class SecurityContextInterceptor extends SecurityContextWebInterceptor implements
    HandlerInterceptor, InitializingBean {

    public void afterPropertiesSet() throws Exception {
        init();
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {
        return preHandle( request, response );
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response,
                            Object handler, ModelAndView modelAndView ) throws Exception {
        postHandle( request, response );
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response,
                                 Object handler, Exception ex ) throws Exception {
        afterCompletion( request, response, ex );
    }

}
