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
import org.jsecurity.util.StringUtils;
import org.jsecurity.web.RedirectView;
import org.jsecurity.web.SecurityWebSupport;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * <p>Base class for all web interceptors. This class is an adapter for the WebInterceptor interface.</p>
 *
 * @author Allan Ditzel
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractWebInterceptor extends SecurityWebSupport implements WebInterceptor {

    protected AntPathMatcher pathMatcher = new AntPathMatcher();

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

    /**
     * A collection of url-to-config entries where the key is the url and the value is the
     * interceptor-specific configuration elements.  The subclass is expected to
     */
    protected Map<String, ?> appliedUrls = null; //url to interceptor-specific-config mapping.


    protected Map<String, Set<String>> tokenizeValues(Map<String,String> urlValueMap) {

        Map<String,Set<String>> converted = new LinkedHashMap<String,Set<String>>(this.appliedUrls.size());

        for( Map.Entry<String,String> entry : urlValueMap.entrySet() ) {
            String url = entry.getKey();
            String interceptorConfig = entry.getValue();
            if ( interceptorConfig != null ) {
                String[] configTokens = StringUtils.split(interceptorConfig);
                Set<String> configTokensSet = new LinkedHashSet<String>( Arrays.asList(configTokens) );
                converted.put(url,configTokensSet);
            }
        }

        if (!converted.isEmpty()) {
            return converted;
        } else {
            return null;
        }
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
            
            //TODO Need to strip off context path here.  See Spring's UrlPathHelper.getPathWithinApplication()

            // If URL path isn't matched, we allow the request to go through so default to true
            boolean continueChain = true;
            for (String url : this.appliedUrls.keySet()) {

                // If the path does match, then pass on to the subclass implementation for specific checks:
                if (pathMatcher.match(url, requestURI)) {
                    continueChain = onPreHandle( request, response, this.appliedUrls.get(url) );
                }

                if ( !continueChain ) {
                    //it is expected the subclass renders the response directly, so just return false
                    return false;
                }
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
