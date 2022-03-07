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

import org.junit.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Collection;
import java.util.Collections;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

/**
 * Test cases for the {@link AuthorizationFilter} class.
 * @since 2.0 
 */
public class IpFilterTest {

    @Test
    public void accessShouldBeDeniedByDefault() throws Exception {
        IpFilter filter = new IpFilter();
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getRemoteAddr()).andReturn("192.168.42.42");
        replay(request);
        assertFalse(filter.isAccessAllowed(request, null, null));
        verify(request);
    }

    @Test
    public void accessShouldBeDeniedWhenNotInTheAllowedSet() throws Exception {
        IpFilter filter = new IpFilter();
        filter.setAuthorizedIps("192.168.33/24");
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getRemoteAddr()).andReturn("192.168.42.42");
        replay(request);
        assertFalse(filter.isAccessAllowed(request, null, null));
        verify(request);
    }

    @Test
    public void accessShouldBeGrantedToIpsInTheAllowedSet() throws Exception {
        IpFilter filter = new IpFilter();
        filter.setAuthorizedIps("192.168.32/24 192.168.33/24 192.168.34/24");
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getRemoteAddr()).andReturn("192.168.33.44");
        replay(request);
        assertFalse(filter.isAccessAllowed(request, null, null));
        verify(request);
    }

    @Test
    public void deniedTakesPrecedenceOverAllowed() throws Exception {
        IpFilter filter = new IpFilter();
        filter.setAuthorizedIps("192.168.0.0/16");
        filter.setDeniedIps("192.168.33.0/24");
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getRemoteAddr()).andReturn("192.168.33.44");
        replay(request);
        assertFalse(filter.isAccessAllowed(request, null, null));
        verify(request);
    }

    @Test
    public void willBlockAndAllowBasedOnIpSource() throws Exception {
        IpSource source = new IpSource() {
                public Collection<String> getAuthorizedIps() {
                    return Collections.singleton("192.168.0.0/16");
                }
                public Collection<String> getDeniedIps() {
                    return Collections.singleton("192.168.33.0/24");
                }
            };
        IpFilter filter = new IpFilter();
        filter.setIpSource(source);
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getRemoteAddr()).andReturn("192.168.33.44");
        replay(request);
        assertFalse(filter.isAccessAllowed(request, null, null));
        verify(request);
    }
}
