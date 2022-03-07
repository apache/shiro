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
 *     <li>Non-ASCII characters - can be disabled by setting {@code blockNonAscii = false}, the ability to disable this check will be removed in future version.</li>
 * </ul>
 *
 * @see <a href="https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/firewall/StrictHttpFirewall.html">This class was inspired by Spring Security StrictHttpFirewall</a>
 * @since 1.6
 */
public class InvalidRequestFilter extends AccessControlFilter {

    private static final List<String> SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));

    private static final List<String> BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));

    private boolean blockSemicolon = true;

    private boolean blockBackslash = !Boolean.getBoolean(WebUtils.ALLOW_BACKSLASH);

    private boolean blockNonAscii = true;

    @Override
    protected boolean isAccessAllowed(ServletRequest req, ServletResponse response, Object mappedValue) throws Exception {
        HttpServletRequest request = WebUtils.toHttp(req);
        // check the original and decoded values
        return isValid(request.getRequestURI())      // user request string (not decoded)
                && isValid(request.getServletPath()) // decoded servlet part
                && isValid(request.getPathInfo());   // decoded path info (may be null)
    }

    private boolean isValid(String uri) {
        return !StringUtils.hasText(uri)
               || ( !containsSemicolon(uri)
                 && !containsBackslash(uri)
                 && !containsNonAsciiCharacters(uri));
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        WebUtils.toHttp(response).sendError(400, "Invalid request");
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
}
