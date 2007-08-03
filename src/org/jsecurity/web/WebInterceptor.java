package org.jsecurity.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @since 0.2
 * @author Les Hazlewood
 */
public interface WebInterceptor {

    boolean preHandle( HttpServletRequest request, HttpServletResponse response ) throws Exception;

    void postHandle( HttpServletRequest request, HttpServletResponse response ) throws Exception;

    void afterCompletion( HttpServletRequest request, HttpServletResponse response, Exception exception ) throws Exception;
}
