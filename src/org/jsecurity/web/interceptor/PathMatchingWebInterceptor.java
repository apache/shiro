/*
 * Copyright (C) 2005-2008 Les Hazlewood
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

package org.jsecurity.web.interceptor;

import org.jsecurity.util.AntPathMatcher;
import static org.jsecurity.util.StringUtils.split;
import org.jsecurity.web.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <p>Base class for web interceptors that will filter only specified paths and allow all others to pass through.</p>
 * 
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class PathMatchingWebInterceptor extends RedirectingWebInterceptor implements PathConfigWebInterceptor {

    protected AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * A collection of path-to-config entries where the key is a path which this interceptor should filter and
     * the value is the (possibly null) configuration element specific to this WebInterceptor for that specific path.
     *
     * <p>To put it another way, the keys are the paths that this Interceptor will filter.
     * <p>The values are interceptor-specific objects that this filter should use when processing the corresponding
     * key (path).  The values can be null if no interceptor-specific config was specified for that url.
     */
    protected Map<String,Object> appliedPaths = new LinkedHashMap<String,Object>();
    

    public void processPathConfig(String path, String config) {
        String[] values = null;
        if ( config != null ) {
            values = split(config);
        }

        this.appliedPaths.put(path,values);
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

        if (this.appliedPaths != null && !this.appliedPaths.isEmpty()) {

            String requestURI = WebUtils.getPathWithinApplication(toHttp(request));

            // If URL path isn't matched, we allow the request to go through so default to true
            boolean continueChain = true;
            for (String path : this.appliedPaths.keySet()) {

                // If the path does match, then pass on to the subclass implementation for specific checks:
                if (pathMatcher.match(path, requestURI)) {
                    if ( log.isTraceEnabled() ) {
                        log.trace( "matched path [" + path + "] for requestURI [" + requestURI + "].  " +
                                "Performing onPreHandle check..." );
                    }
                    Object config = this.appliedPaths.get(path);
                    continueChain = onPreHandle( request, response, config );
                }

                if ( !continueChain ) {
                    //it is expected the subclass renders the response directly, so just return false
                    return false;
                }
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "appliedPaths property is null or empty.  This interceptor will passthrough immediately." );
            }
        }

        return true;
    }

    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object configValue ) throws Exception {
        return true;
    }

    /**
     * Default implementation of this method does nothing - subclasses may override for postHandle logic.
     *
     * @param request
     * @param response
     * @throws Exception
     */
    public void postHandle(ServletRequest request, ServletResponse response) throws Exception {
    }

    /**
     * Default implementation of this method does nothing - subclasses may override for afterCompletion logic.
     *
     * @param request
     * @param response
     * @param exception
     * @throws Exception
     */
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
    }
}
