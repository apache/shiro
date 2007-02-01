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

import org.jsecurity.SecurityManager;
import org.jsecurity.web.WebUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interceptor that is used to ensure an {@link org.jsecurity.context.SecurityContext} is bound to the
 * thread local on every request.  Also ensures that any {@link org.jsecurity.context.SecurityContext} bound to
 * the thread local during a request is stored in the HTTP session when the request is complete.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class ThreadLocalSecurityContextInterceptor extends HandlerInterceptorAdapter {

    private SecurityManager securityManager;


    public void setSecurityManager( SecurityManager securityManager) {
        this.securityManager = securityManager;
    }


    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {

        WebUtils.bindSecurityContextToThread( request, securityManager);
        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response,
                            Object handler, ModelAndView modelAndView ) throws Exception {
        WebUtils.bindSecurityContextToSession( request );
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response,
                                 Object handler, Exception ex ) throws Exception {
        WebUtils.unbindSecurityContextFromThread();
    }

}
