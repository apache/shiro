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
package org.apache.shiro.web.session;

import org.easymock.Capture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpSession;

import static org.easymock.EasyMock.captureInt;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class HttpServletSessionTest {

    private HttpSession mockSession;

    @BeforeEach
    public void setUp() throws Exception {
        this.mockSession = createMock(HttpSession.class);
    }

    /*
     * Shiro-421
     * Tests that the conversion of a httpSession timeout interval from seconds to milliseconds doesn't overflow.
     * @since 1.3
     */
    @Test
    void testLongTimeout() throws Exception {
        // 30 days.
        final int expectedTimeoutInSeconds = 30 * 24 * 60 * 60;
        final long expectedLongValue = expectedTimeoutInSeconds * 1000L;

        Capture<Integer> capturedInt = Capture.newInstance();
        // use a capture to make sure the setter is doing the right thing.
        mockSession.setMaxInactiveInterval(captureInt(capturedInt));
        expect(mockSession.getMaxInactiveInterval()).andReturn(expectedTimeoutInSeconds);
        replay(mockSession);

        HttpServletSession servletSession = new HttpServletSession(mockSession, null);
        servletSession.setTimeout(expectedLongValue);

        long timeoutInMilliseconds = servletSession.getTimeout();

        assertEquals(expectedLongValue, timeoutInMilliseconds);
        assertEquals(expectedTimeoutInSeconds, capturedInt.getValue().intValue());
    }
}
