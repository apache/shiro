/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.filter;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.apache.shiro.util.StringUtils.split;

/**
 * <p>Base class for Filters that will process only specified paths and allow all others to pass through.</p>
 *
 * @since 0.9
 */
public abstract class PathMatchingFilter extends AdviceFilter implements PathConfigProcessor {

    /**
     * Log available to this class only
     */
    private static final Logger log = LoggerFactory.getLogger(PathMatchingFilter.class);

    /**
     * PatternMatcher used in determining which paths to react to for a given request.
     */
    protected PatternMatcher pathMatcher = new AntPathMatcher();

    /**
     * A collection of path-to-config entries where the key is a path which this filter should process and
     * the value is the (possibly null) configuration element specific to this Filter for that specific path.
     *
     * <p>To put it another way, the keys are the paths (urls) that this Filter will process.
     * <p>The values are filter-specific data that this Filter should use when processing the corresponding
     * key (path).  The values can be null if no Filter-specific config was specified for that url.
     */
    protected Map<String, Object> appliedPaths = new LinkedHashMap<String, Object>();

    /**
     * Splits any comma-delmited values that might be found in the <code>config</code> argument and sets the resulting
     * <code>String[]</code> array on the <code>appliedPaths</code> internal Map.
     * <p/>
     * That is:
     * <pre><code>
     * String[] values = null;
     * if (config != null) {
     *     values = split(config);
     * }
     *
     * this.{@link #appliedPaths appliedPaths}.put(path, values);
     * </code></pre>
     *
     * @param path   the application context path to match for executing this filter.
     * @param config the specified for <em>this particular filter only</em> for the given <code>path</code>
     * @return this configured filter.
     */
    public Filter processPathConfig(String path, String config) {
        String[] values = null;
        if (config != null) {
            values = split(config);
        }

        this.appliedPaths.put(path, values);
        return this;
    }

    /**
     * Returns the context path within the application based on the specified <code>request</code>.
     * <p/>
     * This implementation merely delegates to
     * {@link WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) WebUtils.getPathWithinApplication(request)},
     * but can be overridden by subclasses for custom logic.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the context path within the application.
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    /**
     * Returns <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     * <code>false</code> otherwise.
     * <p/>
     * The default implementation acquires the <code>request</code>'s path within the application and determines
     * if that matches:
     * <p/>
     * <code>String requestURI = {@link #getPathWithinApplication(javax.servlet.ServletRequest) getPathWithinApplication(request)};<br/>
     * return {@link #pathsMatch(String, String) pathsMatch(path,requestURI)}</code>
     *
     * @param path    the configured url pattern to check the incoming request against.
     * @param request the incoming ServletRequest
     * @return <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     *         <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String path, ServletRequest request) {
        String requestURI = getPathWithinApplication(request);
        if (log.isTraceEnabled()) {
            log.trace("Attempting to match pattern [" + path + "] with current requestURI [" + requestURI + "]...");
        }
        return pathsMatch(path, requestURI);
    }

    /**
     * Returns <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     * <code>false</code> otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>this.pathMatcher.{@link PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>,
     * but can be overridden by subclasses for custom matching behavior.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified <code>pattern</code>
     * @return <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     *         <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String pattern, String path) {
        return pathMatcher.matches(pattern, path);
    }

    /**
     * Implementation that handles path-matching behavior before a request is evaluated.  If the path matches,
     * the request will be allowed through via the result from
     * {@link #onPreHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) onPreHandle}.  If the
     * path does not match, this filter will allow passthrough immediately.
     *
     * <p>In order to retain path-matching functionality, subclasses should not override this method if at all
     * possible, and instead override
     * {@link #onPreHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) onPreHandle} instead.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return true - allow the request chain to continue in this default implementation
     * @throws Exception
     */
    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

        if (this.appliedPaths == null || this.appliedPaths.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("appliedPaths property is null or empty.  This Filter will passthrough immediately.");
            }
            return true;
        }

        for (String path : this.appliedPaths.keySet()) {
            // If the path does match, then pass on to the subclass implementation for specific checks
            //(first match 'wins'):
            if (pathsMatch(path, request)) {
                if (log.isTraceEnabled()) {
                    log.trace("Current requestURI matches pattern [" + path + "].  Performing onPreHandle check...");
                }
                Object config = this.appliedPaths.get(path);
                return onPreHandle(request, response, config);
            }
        }

        //no path matched, allow the request to go through:
        return true;
    }

    /**
     * Default implementation always returns <code>true</code>.  Should be overridden by subclasses for custom
     * logic.
     *
     * @param request     the incoming ServletRequest
     * @param response    the outgoing ServletResponse
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings.
     * @return <code>true</code> if the request should be able to continue, <code>false</code> if the filter will
     *         handle the response directly.
     * @throws Exception if an error occurs
     */
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return true;
    }
}
