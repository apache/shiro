/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.web.filter.authz;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

/**
 * @since 2.0 
 */
public class IpAddressMatcherTests {
    final IpAddressMatcher v6matcher = new IpAddressMatcher("fe80::21f:5bff:fe33:bd68");
    final IpAddressMatcher v4matcher = new IpAddressMatcher("192.168.1.104");
    final String ipv6Address = "fe80::21f:5bff:fe33:bd68";
    final String ipv4Address = "192.168.1.104";

    @Test
    public void ipv6MatcherMatchesIpv6Address() {
        assertTrue(v6matcher.matches(ipv6Address));
    }
    
    @Test
    public void ipv6MatcherDoesntMatchIpv4Address() {
        assertFalse(v6matcher.matches(ipv4Address));
    }
    
    @Test
    public void ipv4MatcherMatchesIpv4Address() {
        assertTrue(v4matcher.matches(ipv4Address));
    }
    
    @Test
    public void ipv4SubnetMatchesCorrectly() throws Exception {
        IpAddressMatcher matcher = new IpAddressMatcher("192.168.1.0/24");
        assertTrue(matcher.matches(ipv4Address));
        matcher = new IpAddressMatcher("192.168.1.128/25");
        assertFalse(matcher.matches(ipv4Address));
        assertTrue(matcher.matches("192.168.1.159"));
    }
    
    @Test
    public void ipv6RangeMatches() throws Exception {
        IpAddressMatcher matcher = new IpAddressMatcher("2001:DB8::/48");
        assertTrue(matcher.matches("2001:DB8:0:0:0:0:0:0"));
        assertTrue(matcher.matches("2001:DB8:0:0:0:0:0:1"));
        assertTrue(matcher.matches("2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF"));
        assertFalse(matcher.matches("2001:DB8:1:0:0:0:0:0"));
    }
    
    // https://github.com/spring-projects/spring-security/issues/1970q
    @Test
    public void zeroMaskMatchesAnything() throws Exception {
        IpAddressMatcher matcher = new IpAddressMatcher("0.0.0.0/0");
        
        assertTrue(matcher.matches("123.4.5.6"));
        assertTrue(matcher.matches("192.168.0.159"));
        
        matcher = new IpAddressMatcher("192.168.0.159/0");
        assertTrue(matcher.matches("123.4.5.6"));
        assertTrue(matcher.matches("192.168.0.159"));
    }
}
