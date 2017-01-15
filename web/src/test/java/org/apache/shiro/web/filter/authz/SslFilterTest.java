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

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Test;

import static org.apache.shiro.web.filter.authz.SslFilter.HSTS.*;
import org.easymock.Capture;
import org.easymock.CaptureType;
import static org.easymock.EasyMock.*;
import org.easymock.IAnswer;
import static org.junit.Assert.*;
import org.junit.Before;

public class SslFilterTest {
    
    private HttpServletRequest request;
    private HttpServletResponse response;
    private SslFilter sslFilter;
    
    @Before
    public void before() {
        request = createNiceMock(HttpServletRequest.class);
        response = createNiceMock(HttpServletResponse.class);
        sslFilter = new SslFilter();
        
        final Map<String,String> headers = new HashMap<String,String>();
        
        final Capture<String> capturedName = newCapture();
        final Capture<String> capturedValue = newCapture();
        
        // mock HttpServletResponse.getHeader
        expect(response.getHeader(capture(capturedName))).andAnswer(new IAnswer<String>() {
            @Override
            public String answer() throws Throwable {
                String name = capturedName.getValue();
                return headers.get(name);
            }
            
        });
        
        // mock HttpServletResponse.addHeader
        response.addHeader(capture(capturedName), capture(capturedValue));
        expectLastCall().andAnswer(new IAnswer<Void>() {
            @Override
            public Void answer() throws Throwable {
                String name = capturedName.getValue();
                String value = capturedValue.getValue();
                headers.put(name, value);
                return (null);
            }
        });
        
        replay(response);
    }

    @Test
    public void testDisabledByDefault() {
        sslFilter.postHandle(request, response);
        assertNull(response.getHeader(HTTP_HEADER));
    }

    @Test
    public void testDefaultValues() {
        sslFilter.getHsts().setEnabled(true);
        sslFilter.postHandle(request, response);
        assertEquals("max-age=" + DEFAULT_MAX_AGE, response.getHeader(HTTP_HEADER));
    }
    
    @Test
    public void testSetProperties() {
        sslFilter.getHsts().setEnabled(true);
        sslFilter.getHsts().setMaxAge(7776000);
        sslFilter.getHsts().setIncludeSubDomains(true);
        sslFilter.postHandle(request, response);
        
        String expected = "max-age=" + 7776000 + "; includeSubDomains";

        assertEquals(expected, response.getHeader(HTTP_HEADER));
    }
    
}
