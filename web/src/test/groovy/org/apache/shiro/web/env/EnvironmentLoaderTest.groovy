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
package org.apache.shiro.web.env

import org.easymock.Capture
import org.easymock.IAnswer

import java.util.concurrent.atomic.AtomicInteger;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;
import org.junit.Test

import javax.servlet.ServletContext

/**
 * Unit tests for the {@link EnvironmentLoaderTest} implementation.
 * 
 * @since 1.3
 */
class EnvironmentLoaderTest {

    @Test
    void testCustomizeAndFinalizeEnvironment() {

        final AtomicInteger customizeEnvironmentCalledTimes = new AtomicInteger(0);
        final AtomicInteger finalizeEnvironmentCalledTimes = new AtomicInteger(0);

        EnvironmentLoader environmentLoader = new EnvironmentLoader() {

            // EasyMock supports partial mocks, and this should not be necessary, but I could not get the .times()
            // to work correctly.
            @Override
            protected void customizeEnvironment(WebEnvironment environment) {
                customizeEnvironmentCalledTimes.getAndIncrement();
            }

            @Override
            protected void finalizeEnvironment(WebEnvironment environment) {
                finalizeEnvironmentCalledTimes.getAndIncrement();
            }
        };

        ServletContext servletContext = createNiceMock(ServletContext.class);
        Capture<Object> environmentObjectCapture = new Capture<Object>();
        // This class is loaded via ClassUtils.newInstance()
        expect(servletContext.getInitParameter(EnvironmentLoader.ENVIRONMENT_CLASS_PARAM)).andReturn(MockWebEnvironment.class.getName());
        servletContext.setAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY), capture(environmentObjectCapture));
        expect(servletContext.getAttribute(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY)).andReturn(null); // the first time it will be null
        // after that use what was passed to the setAttribute method
        expect(servletContext.getAttribute(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY)).andAnswer(new IAnswer<Object>() {
            @Override
            Object answer() throws Throwable {
                return environmentObjectCapture.getValue();
            }
        })

        replay(servletContext);

        // initEnvironment calls customizeEnvironment
        environmentLoader.initEnvironment(servletContext);
        assertEquals(1, customizeEnvironmentCalledTimes.get())
        assertEquals(0, finalizeEnvironmentCalledTimes.get())

        // destroyEnvironment calls finalizeEnvironment
        environmentLoader.destroyEnvironment(servletContext);
        assertEquals(1, customizeEnvironmentCalledTimes.get())
        assertEquals(1, finalizeEnvironmentCalledTimes.get())


    }
}
