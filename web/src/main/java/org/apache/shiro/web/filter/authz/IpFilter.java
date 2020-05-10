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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Collection;

/**
 * A Filter that requires the request to be from within a specific set of IP
 * address ranges and / or not from with a specific (denied) set.
 * <p/>
 * Example config:
 * <pre>
 * [main]
 * localLan = org.apache.shiro.web.filter.authz.IpFilter
 * localLan.authorizedIps = 192.168.10.0/24
 * localLan.deniedIps = 192.168.10.10/32
 * <p/>
 * [urls]
 * /some/path/** = localLan
 * # override for just this path:
 * /another/path/** = localLan
 * </pre>
 *
 * @since 2.0 
 */
public class IpFilter extends AuthorizationFilter {

    private static IpSource DEFAULT_IP_SOURCE = new IpSource() {
            public Collection<String> getAuthorizedIps() {
                return Collections.emptySet();
            }
            public Collection<String> getDeniedIps() {
                return Collections.emptySet();
            }
        };
    
    private IpSource ipSource = DEFAULT_IP_SOURCE;

    private List<IpAddressMatcher> authorizedIpMatchers = Collections.emptyList();
    private List<IpAddressMatcher> deniedIpMatchers = Collections.emptyList();

    /**
     * Specifies a set of (comma, tab or space-separated) strings representing
     * IP address representing IPv4 or IPv6 ranges / CIDRs from which access
     * should be allowed (if the IP is not included in either the list of
     * statically defined denied IPs or the dynamic list of IPs obtained from
     * the IP source.
     */
    public void setAuthorizedIps(String authorizedIps) {
        String[] ips = StringUtils.tokenizeToStringArray(authorizedIps, ", \t");
        if (ips != null && ips.length > 0) {
            authorizedIpMatchers = new ArrayList<IpAddressMatcher>();
            for (String ip : ips) {
                authorizedIpMatchers.add(new IpAddressMatcher(ip));
            }
        }
    }

    /**
     * Specified a set of (comma, tab or space-separated) strings representing
     * IP address representing IPv4 or IPv6 ranges / CIDRs from which access
     * should be blocked.
     */
    public void setDeniedIps(String deniedIps) {
        String[] ips = StringUtils.tokenizeToStringArray(deniedIps, ", \t");
        if (ips != null && ips.length > 0) {
            deniedIpMatchers = new ArrayList<IpAddressMatcher>();
            for (String ip : ips) {
                deniedIpMatchers.add(new IpAddressMatcher(ip));
            }
        }
    }

    public void setIpSource(IpSource source) {
        this.ipSource = source;
    }

    /**
     * Returns the remote host for a given HTTP request. By default uses the
     * remote method ServletRequest.getRemoteAddr(). May be overriden by
     * subclasses to obtain address information from specific headers (e.g. XFF
     * or Forwarded) in situations with reverse proxies.
     */
    public String getHostFromRequest(ServletRequest request) {
        return request.getRemoteAddr();
    }

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        String remoteIp = getHostFromRequest(request);
        for (IpAddressMatcher matcher : deniedIpMatchers) {
            if (matcher.matches(remoteIp)) {
                return false;
            }
        }
        for (String ip : ipSource.getDeniedIps()) {
            IpAddressMatcher matcher = new IpAddressMatcher(ip);
            if (matcher.matches(remoteIp)) {
                return false;
            }
        }
        for (IpAddressMatcher matcher : authorizedIpMatchers) {
            if (matcher.matches(remoteIp)) {
                return true;
            }
        }
        for (String ip : ipSource.getAuthorizedIps()) {
            IpAddressMatcher matcher = new IpAddressMatcher(ip);
            if (matcher.matches(remoteIp)) {
                return true;
            }
        }
        return false;
    }
}
