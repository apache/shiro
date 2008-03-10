/*
 * Copyright (C) 2005-2008 Allan Ditzel, Les Hazlewood
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
import org.jsecurity.util.AntPathMatcher;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Map;

/**
 * <p>Base class for all web interceptors. This class is an adapter for the WebInterceptor interface.</p>
 *
 * @author Allan Ditzel
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractWebInterceptor extends SecurityWebSupport implements WebInterceptor {

    protected AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * A collection of url-to-config entries where the key is the url and the value is the
     * interceptor-specific configuration elements.  The subclass is expected to
     */
    protected Map<String, ?> appliedUrls = null; //url to interceptor-specific-config mapping.

    /**
     * Default implementation
     *
     * @throws JSecurityException
     */
    public void init() throws JSecurityException {
    }

    /**
     * Sets the URLs that this interceptor should filter.
     *
     * <p>The map is a url (key) to interceptor-specific config string (value) entries.  Subclasses are expected to
     * process the config strings (map values) for the corresponding urls (keys).
     *
     * <p>It is expected that the implementation will ignore all requests to urls <em>not</em> matched by those in
     * this map.
     *
     * @param urlToConfigMap
     */
    public void setAppliedUrls(Map<String, String> urlToConfigMap) {
        this.appliedUrls = urlToConfigMap;
    }

    /**
     * Default implemenation of this method. Always returns true. Sub-classes should override this method.
     *
     * @param request
     * @param response
     * @return true - allow the request chain to continue in this default implementation
     * @throws Exception
     */
    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

        if (this.appliedUrls != null && !this.appliedUrls.isEmpty()) {

            String requestURI = toHttp(request).getRequestURI();
            
            //todo Need to strip off context path here.  See Spring's UrlPathHelper.getPathWithinApplication()

            // If URL path isn't matched, we assume that the user is authorized - so default to true
            boolean continueChain = true;
            for (String url : this.appliedUrls.keySet()) {

                // If the path does match, then pass on to the subclass implementation for specific checks:
                if (pathMatcher.match(url, requestURI)) {
                    continueChain = onPreHandle( request, response );
                }

                if ( !continueChain ) {
                    return false;
                }
            }
        }

        return true;
    }

    protected boolean onPreHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    /**
     * Default implementation of this method. Sub-classes should override this method.
     *
     * @param request
     * @param response
     * @throws Exception
     */
    public void postHandle(ServletRequest request, ServletResponse response) throws Exception {
    }

    /**
     * Default implementation of this method. Sub-classes should override this method.
     *
     * @param request
     * @param response
     * @param exception
     * @throws Exception
     */
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
    }
}
