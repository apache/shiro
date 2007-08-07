/*
 * Copyright (C) 2005 Les Hazlewood Jeremy Haile
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

import org.jsecurity.web.support.AuthenticationWebInterceptor;
import org.jsecurity.web.support.RedirectView;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Simple interceptor that verifies a user is authenticated (logged-in) before allowing a
 * page to be viewd.
 *
 * <p>If the user is not authenticated, they will be redirected to the login page located
 * at the URL {@link #getRedirectUrl() getRedirectUrl()}.  Just prior to being redirected, the
 * page URL they attempted to view is first saved in a
 * {@link #setAttemptedPageStorageScheme configurable location} for lookup later.
 *
 * <p>Upon a successful login, the login controller may look in this location for the attempted page url
 * and then forward the user to that attempted page - a nice usability feature in most systems.
 *
 * <p>The default redirect implementation is accomplished via a
 * {@link RedirectView RedirectView}, {@link RedirectView#renderMergedOutputModel(java.util.Map, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)}  rendered} with
 * a <tt>null</tt> model <tt>Map</tt>.  The
 * {@link #setContextRelative contextRelative}, {@link #setHttp10Compatible http10Compatible} and
 * {@link #setEncodingScheme encodingScheme} are passthrough attributes that will be set on the
 * <tt>RedirectView</tt> that is created to process the redirect.  Set them according to the
 * {@link RedirectView RedirectView} JavaDoc.
 *
 * @see RedirectView RedirectView
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class AuthenticationInterceptor extends AuthenticationWebInterceptor
    implements HandlerInterceptor, InitializingBean {
                                                    
    public void afterPropertiesSet() throws Exception {
        init();
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response, Object handler )
        throws Exception {
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
