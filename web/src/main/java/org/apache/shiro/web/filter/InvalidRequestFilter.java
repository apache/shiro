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

import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A request filter that blocks malicious requests. Invalid request will respond with a 400 response code.
 * <p>
 * This filter checks and blocks the request if the following characters are found in the request URI:
 * <ul>
 *     <li>Semicolon - can be disabled by setting {@code blockSemicolon = false}</li>
 *     <li>Backslash - can be disabled by setting {@code blockBackslash = false}</li>
 *     <li>Non-ASCII characters - can be disabled by setting {@code blockNonAscii = false},
 *     the ability to disable this check will be removed in future version.</li>
 *     <li>Path traversals - can be disabled by setting {@code blockTraversal = false}</li>
 * </ul>
 *
 * This class was inspired by Spring Security StrictHttpFirewall
 * @since 1.6
 */
public class InvalidRequestFilter extends AccessControlFilter {

    enum PathTraversalBlockMode {
        STRICT,
        NORMAL,
        NO_BLOCK;
    }

    private static final List<String> SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));

    private static final List<String> BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));

    private static final List<String> FORWARDSLASH = Collections.unmodifiableList(Arrays.asList("%2f", "%2F"));

    private static final List<String> PERIOD = Collections.unmodifiableList(Arrays.asList("%2e", "%2E"));

    private boolean blockSemicolon = true;

    private boolean blockBackslash = !WebUtils.isAllowBackslash();

    private boolean blockNonAscii = true;

    private PathTraversalBlockMode pathTraversalBlockMode = PathTraversalBlockMode.NORMAL;

    @Override
    protected boolean isAccessAllowed(ServletRequest req, ServletResponse response, Object mappedValue) throws Exception {
        HttpServletRequest request = WebUtils.toHttp(req);
        // check the original and decoded values

        // user request string (not decoded)
        return isValid(request.getRequestURI())
                // decoded servlet part
                && isValid(request.getServletPath())
                // decoded path info (maybe null)
                && isValid(request.getPathInfo());
    }

    private boolean isValid(String uri) {
        return !StringUtils.hasText(uri)
                || (!containsSemicolon(uri)
                && !containsBackslash(uri)
                && !containsNonAsciiCharacters(uri))
                && !containsTraversal(uri);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        WebUtils.toHttp(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request");
        return false;
    }

    private boolean containsSemicolon(String uri) {
        if (isBlockSemicolon()) {
            return SEMICOLON.stream().anyMatch(uri::contains);
        }
        return false;
    }

    private boolean containsBackslash(String uri) {
        if (isBlockBackslash()) {
            return BACKSLASH.stream().anyMatch(uri::contains);
        }
        return false;
    }

    private boolean containsNonAsciiCharacters(String uri) {
        if (isBlockNonAscii()) {
            return !containsOnlyPrintableAsciiCharacters(uri);
        }
        return false;
    }

    private static boolean containsOnlyPrintableAsciiCharacters(String uri) {
        int length = uri.length();
        for (int i = 0; i < length; i++) {
            char c = uri.charAt(i);
            if (c < '\u0020' || c > '\u007e') {
                return false;
            }
        }
        return true;
    }

    private boolean containsTraversal(String uri) {
        if (isBlockTraversalNormal()) {
            return !(isNormalized(uri));
        }
        if (isBlockTraversalStrict()) {
            return !(isNormalized(uri)
                    && PERIOD.stream().noneMatch(uri::contains)
                    && FORWARDSLASH.stream().noneMatch(uri::contains));
        }
        return false;
    }

    /**
     * Checks whether a path is normalized (doesn't contain path traversal sequences like
     * "./", "/../" or "/.")
     *
     * @param path the path to test
     * @return true if the path doesn't contain any path-traversal character sequences.
     */
    private boolean isNormalized(String path) {
        if (path == null) {
            return true;
        }
        for (int i = path.length(); i > 0; ) {
            int slashIndex = path.lastIndexOf('/', i - 1);
            int gap = i - slashIndex;
            if (gap == 2 && path.charAt(slashIndex + 1) == '.') {
                // ".", "/./" or "/."
                return false;
            }
            if (gap == 3 && path.charAt(slashIndex + 1) == '.' && path.charAt(slashIndex + 2) == '.') {
                return false;
            }
            i = slashIndex;
        }
        return true;
    }

    public boolean isBlockSemicolon() {
        return blockSemicolon;
    }

    public void setBlockSemicolon(boolean blockSemicolon) {
        this.blockSemicolon = blockSemicolon;
    }

    public boolean isBlockBackslash() {
        return blockBackslash;
    }

    public void setBlockBackslash(boolean blockBackslash) {
        this.blockBackslash = blockBackslash;
    }

    public boolean isBlockNonAscii() {
        return blockNonAscii;
    }

    public void setBlockNonAscii(boolean blockNonAscii) {
        this.blockNonAscii = blockNonAscii;
    }

    public boolean isBlockTraversalNormal() {
        return pathTraversalBlockMode == PathTraversalBlockMode.NORMAL;
    }

    public boolean isBlockTraversalStrict() {
        return pathTraversalBlockMode == PathTraversalBlockMode.STRICT;
    }

    public void setPathTraversalBlockMode(PathTraversalBlockMode mode) {
        this.pathTraversalBlockMode = mode;
    }

    /**
     *
     * @deprecated Use {@link #setPathTraversalBlockMode(PathTraversalBlockMode)}
     */
    @Deprecated
    public void setBlockTraversal(boolean blockTraversal) {
        this.pathTraversalBlockMode = blockTraversal ? PathTraversalBlockMode.NORMAL : PathTraversalBlockMode.NO_BLOCK;
    }
}
