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
package org.jsecurity.spring.servlet.security;

import org.jsecurity.session.Session;
import org.jsecurity.web.support.DefaultSessionWebInterceptor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Ensures a JSecurity {@link Session Session} exists for an incoming {@link HttpServletRequest}.
 * <p/>
 * <p>If an existing <tt>Session</tt> can be found that is already associated with the client
 * executing the <tt>HttpServletRequest</tt>, it will be retrieved and made accessible.
 * <p/>
 * <p>If no existing <tt>Session</tt> could be associated with the <tt>HttpServletRequest</tt>,
 * this interceptor will create a new one, associate it with the <tt>request</tt>'s corresponding
 * client, and be made accessible to the JSecurity framework for the duration of the
 * request (i.e. via a {@link ThreadLocal ThreadLocal}).
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class SessionInterceptor extends DefaultSessionWebInterceptor implements HandlerInterceptor, InitializingBean {

    public void afterPropertiesSet() throws Exception {
        super.init();
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {
        super.preHandle( request, response );
        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView ) throws Exception {
        super.postHandle( request, response, null );
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response,
                                 Object handler, Exception ex ) throws Exception {
        super.afterCompletion( request, response, null, ex );
    }
}
