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
package org.apache.shiro.web.filter.mgt;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.util.WebUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code FilterChainResolver} that resolves {@link FilterChain}s based on url path
 * matching, as determined by a configurable {@link #setPathMatcher(org.apache.shiro.lang.util.PatternMatcher) PathMatcher}.
 * <p/>
 * This implementation functions by consulting a {@link org.apache.shiro.web.filter.mgt.FilterChainManager} for all configured filter chains (keyed
 * by configured path pattern).  If an incoming Request path matches one of the configured path patterns (via
 * the {@code PathMatcher}, the corresponding configured {@code FilterChain} is returned.
 *
 * @since 1.0
 */
public class PathMatchingFilterChainResolver implements FilterChainResolver {

    private static transient final Logger log = LoggerFactory.getLogger(PathMatchingFilterChainResolver.class);

    private FilterChainManager filterChainManager;

    private PatternMatcher pathMatcher;

    private static final String DEFAULT_PATH_SEPARATOR = "/";

    public PathMatchingFilterChainResolver() {
        this.pathMatcher = new AntPathMatcher();
        this.filterChainManager = new DefaultFilterChainManager();
    }

    public PathMatchingFilterChainResolver(FilterConfig filterConfig) {
        this.pathMatcher = new AntPathMatcher();
        this.filterChainManager = new DefaultFilterChainManager(filterConfig);
    }

    /**
     * Returns the {@code PatternMatcher} used when determining if an incoming request's path
     * matches a configured filter chain.  Unless overridden, the
     * default implementation is an {@link org.apache.shiro.lang.util.AntPathMatcher AntPathMatcher}.
     *
     * @return the {@code PatternMatcher} used when determining if an incoming request's path
     *         matches a configured filter chain.
     */
    public PatternMatcher getPathMatcher() {
        return pathMatcher;
    }

    /**
     * Sets the {@code PatternMatcher} used when determining if an incoming request's path
     * matches a configured filter chain.  Unless overridden, the
     * default implementation is an {@link org.apache.shiro.lang.util.AntPathMatcher AntPathMatcher}.
     *
     * @param pathMatcher the {@code PatternMatcher} used when determining if an incoming request's path
     *                    matches a configured filter chain.
     */
    public void setPathMatcher(PatternMatcher pathMatcher) {
        this.pathMatcher = pathMatcher;
    }

    public FilterChainManager getFilterChainManager() {
        return filterChainManager;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setFilterChainManager(FilterChainManager filterChainManager) {
        this.filterChainManager = filterChainManager;
    }

    public FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain) {
        FilterChainManager filterChainManager = getFilterChainManager();
        if (!filterChainManager.hasChains()) {
            return null;
        }

        final String requestURI = getPathWithinApplication(request);
        final String requestURINoTrailingSlash = removeTrailingSlash(requestURI);

        //the 'chain names' in this implementation are actually path patterns defined by the user.  We just use them
        //as the chain name for the FilterChainManager's requirements
        for (String pathPattern : filterChainManager.getChainNames()) {
            // If the path does match, then pass on to the subclass implementation for specific checks:
            if (pathMatches(pathPattern, requestURI)) {
                if (log.isTraceEnabled()) {
                    log.trace("Matched path pattern [{}] for requestURI [{}].  " +
                            "Utilizing corresponding filter chain...", pathPattern, Encode.forHtml(requestURI));
                }
                return filterChainManager.proxy(originalChain, pathPattern);
            } else {

                // in spring web, the requestURI "/resource/menus" ---- "resource/menus/" bose can access the resource
                // but the pathPattern match "/resource/menus" can not match "resource/menus/"
                // user can use requestURI + "/" to simply bypassed chain filter, to bypassed shiro protect

                pathPattern = removeTrailingSlash(pathPattern);

                if (pathMatches(pathPattern, requestURINoTrailingSlash)) {
                    if (log.isTraceEnabled()) {
                        log.trace("Matched path pattern [{}] for requestURI [{}].  " +
                                  "Utilizing corresponding filter chain...", pathPattern, Encode.forHtml(requestURINoTrailingSlash));
                    }
                    return filterChainManager.proxy(originalChain, requestURINoTrailingSlash);
                }
            }
        }

        return null;
    }

    /**
     * Returns {@code true} if an incoming request path (the {@code path} argument)
     * matches a configured filter chain path (the {@code pattern} argument), {@code false} otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>{@link #getPathMatcher() getPathMatcher()}.{@link org.apache.shiro.lang.util.PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>.
     * Subclass implementors should think carefully before overriding this method, as typically a custom
     * {@code PathMatcher} should be configured for custom path matching behavior instead.  Favor OO composition
     * rather than inheritance to limit your exposure to Shiro implementation details which may change over time.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified {@code pattern}
     * @return {@code true} if the request {@code path} matches the specified filter chain url {@code pattern},
     *         {@code false} otherwise.
     */
    protected boolean pathMatches(String pattern, String path) {
        PatternMatcher pathMatcher = getPathMatcher();
        return pathMatcher.matches(pattern, path);
    }

    /**
     * Merely returns
     * <code>WebUtils.{@link org.apache.shiro.web.util.WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) getPathWithinApplication(request)}</code>
     * and can be overridden by subclasses for custom request-to-application-path resolution behavior.
     *
     * @param request the incoming {@code ServletRequest}
     * @return the request's path within the appliation.
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    private static String removeTrailingSlash(String path) {
        if(path != null && !DEFAULT_PATH_SEPARATOR.equals(path)
           && path.endsWith(DEFAULT_PATH_SEPARATOR)) {
            return path.substring(0, path.length() - 1);
        }
        return path;
    }
}
