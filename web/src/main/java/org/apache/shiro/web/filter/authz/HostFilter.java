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
package org.apache.shiro.web.filter.authz;

import org.apache.shiro.lang.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.regex.Pattern;
import java.util.Map;

/**
 * A Filter that can allow or deny access based on the host that sent the request.
 *
 * <b>WARNING:</b> NOT YET FULLY IMPLEMENTED!!!  Work in progress.
 *
 * @since 1.0
 */
public class HostFilter extends AuthorizationFilter {

    public static final String IPV4_QUAD_REGEX = "(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2(?:[0-4][0-9]|5[0-5]))";

    public static final String IPV4_REGEX = "(?:" + IPV4_QUAD_REGEX + "\\.){3}" + IPV4_QUAD_REGEX + "$";
    public static final Pattern IPV4_PATTERN = Pattern.compile(IPV4_REGEX);

    public static final String PRIVATE_CLASS_B_SUBSET = "(?:1[6-9]|2[0-9]|3[0-1])";

    public static final String PRIVATE_CLASS_A_REGEX = "10\\.(?:" + IPV4_QUAD_REGEX + "\\.){2}" + IPV4_QUAD_REGEX + "$";

    public static final String PRIVATE_CLASS_B_REGEX =
            "172\\." + PRIVATE_CLASS_B_SUBSET + "\\." + IPV4_QUAD_REGEX + "\\." + IPV4_QUAD_REGEX + "$";

    public static final String PRIVATE_CLASS_C_REGEX = "192\\.168\\." + IPV4_QUAD_REGEX + "\\." + IPV4_QUAD_REGEX + "$";

    Map<String, String> authorizedIps; //user-configured IP (which can be wildcarded) to constructed regex mapping
    Map<String, String> deniedIps;
    Map<String, String> authorizedHostnames;
    Map<String, String> deniedHostnames;


    public void setAuthorizedHosts(String authorizedHosts) {
        if (!StringUtils.hasText(authorizedHosts)) {
            throw new IllegalArgumentException("authorizedHosts argument cannot be null or empty.");
        }
        String[] hosts = StringUtils.tokenizeToStringArray(authorizedHosts, ", \t");

        for (String host : hosts) {
            //replace any periods with \\. to ensure the regex works:
            String periodsReplaced = host.replace(".", "\\.");
            //check for IPv4:
            String wildcardsReplaced = periodsReplaced.replace("*", IPV4_QUAD_REGEX);

            if (IPV4_PATTERN.matcher(wildcardsReplaced).matches()) {
                authorizedIps.put(host, wildcardsReplaced);
            } else {

            }


        }

    }

    public void setDeniedHosts(String deniedHosts) {
        if (!StringUtils.hasText(deniedHosts)) {
            throw new IllegalArgumentException("deniedHosts argument cannot be null or empty.");
        }
    }

    protected boolean isIpv4Candidate(String host) {
        String[] quads = StringUtils.tokenizeToStringArray(host, ".");
        if (quads == null || quads.length != 4) {
            return false;
        }
        for (String quad : quads) {
            if (!quad.equals("*")) {
                try {
                    Integer.parseInt(quad);
                } catch (NumberFormatException nfe) {
                    return false;
                }
            }
        }
        return true;
    }

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        throw new UnsupportedOperationException("Not yet fully implemented!!!" );
    }
}
