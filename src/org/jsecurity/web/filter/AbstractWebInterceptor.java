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

package org.jsecurity.web.filter;

import org.jsecurity.JSecurityException;
import org.jsecurity.util.AntPathMatcher;
import static org.jsecurity.util.StringUtils.split;
import org.jsecurity.web.RedirectView;
import org.jsecurity.web.SecurityWebSupport;
import org.jsecurity.web.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <p>Base class for all web interceptors. This class is an adapter for the WebInterceptor interface.</p>
 *
 * @author Allan Ditzel
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractWebInterceptor extends SecurityWebSupport implements MatchingWebInterceptor {

    protected AntPathMatcher pathMatcher = new AntPathMatcher();
    /**
     * A collection of path-to-config entries where the key is the path and the value is the
     * interceptor-specific configuration element.
     */
    protected Map<String,Object> appliedPaths = new LinkedHashMap<String,Object>(); //path to interceptor-specific-config mapping.

    private String url;
    private boolean contextRelative = true;
	private boolean http10Compatible = true;
	private String encodingScheme = RedirectView.DEFAULT_ENCODING_SCHEME;
    private Map queryParams = new HashMap();

    public AbstractWebInterceptor(){}

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isContextRelative() {
        return contextRelative;
    }

    public void setContextRelative(boolean contextRelative) {
        this.contextRelative = contextRelative;
    }

    public boolean isHttp10Compatible() {
        return http10Compatible;
    }

    public void setHttp10Compatible(boolean http10Compatible) {
        this.http10Compatible = http10Compatible;
    }

    public String getEncodingScheme() {
        return encodingScheme;
    }

    public void setEncodingScheme(String encodingScheme) {
        this.encodingScheme = encodingScheme;
    }

    public Map getQueryParams() {
        return queryParams;
    }

    public void setQueryParams(Map queryParams) {
        this.queryParams = queryParams;
    }

    /**
     * Default implementation
     *
     * @throws JSecurityException
     */
    public void init() throws JSecurityException {
    }

    protected void issueRedirect(ServletRequest request, ServletResponse response ) throws IOException {
        RedirectView view = new RedirectView( getUrl(), isContextRelative(), isHttp10Compatible() );
        view.renderMergedOutputModel(getQueryParams(), toHttp(request), toHttp(response) );
    }

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

    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue ) throws Exception {
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
