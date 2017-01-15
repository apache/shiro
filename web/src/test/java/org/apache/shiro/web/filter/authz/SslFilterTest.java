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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Test;

import static org.apache.shiro.web.filter.authz.SslFilter.HSTS.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class SslFilterTest {

    @Test
    public void testDisabledByDefault() {
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);

        SslFilter sslFilter = new SslFilter();

        sslFilter.postHandle(request, response);
        assertNull(response.getHeader(HTTP_HEADER));
    }

    @Test
    public void testDefaultValues() {
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);

//        String expected = new StringBuilder()
//                .append(HTTP_HEADER)
//                .append(": ")
//                .append("max-age=")
//                .append(DEFAULT_MAX_AGE)
//                .toString();
//        expect(response.addHeader(expected, expected))
//                .andReturn(expected)
//                .anyTimes();
        replay(response);
//        
        SslFilter sslFilter = new SslFilter();
        sslFilter.getHsts().setEnabled(true);

        sslFilter.postHandle(request, response);

        //assertEquals(expected, response.getHeader(HTTP_HEADER));
    }

}
