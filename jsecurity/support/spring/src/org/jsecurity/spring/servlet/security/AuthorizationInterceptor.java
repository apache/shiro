package org.jsecurity.spring.servlet.security;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.servlet.ModelAndView;
import org.jsecurity.ri.web.WebUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created on: Oct 13, 2005 6:47:29 PM
 *
 * @author Les Hazlewood
 */
public class AuthorizationInterceptor extends HandlerInterceptorAdapter {

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {

        WebUtils.bindAuthorizationContextToThread( request );
        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response,
                            Object handler, ModelAndView modelAndView ) throws Exception {
        WebUtils.bindAuthorizationContextToSession( request );
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response,
                                 Object handler, Exception ex ) throws Exception {
        WebUtils.unbindAuthorizationContextFromThread();
    }

}
