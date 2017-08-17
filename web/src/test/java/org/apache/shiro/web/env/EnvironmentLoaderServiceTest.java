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
package org.apache.shiro.web.env;

import org.apache.shiro.config.ConfigurationException;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.ServletContext;
import java.util.Arrays;
import java.util.List;
import java.util.ServiceLoader;

import static org.easymock.EasyMock.expect;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.*;

/**
 * Tests for {@link EnvironmentLoader} that depend on PowerMock the stub out a ServiceLoader.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(EnvironmentLoader.class)
public class EnvironmentLoaderServiceTest {

    @Test()
    public void singleServiceTest() throws Exception {

        List<WebEnvironmentStub> environmentList = Arrays.asList(new WebEnvironmentStub());

        ServletContext servletContext = EasyMock.mock(ServletContext.class);
        expect(servletContext.getInitParameter("shiroEnvironmentClass")).andReturn(null);
        expect(servletContext.getInitParameter("shiroConfigLocations")).andReturn(null);

        PowerMock.mockStaticPartialStrict(ServiceLoader.class, "load");

        final ServiceLoader serviceLoader = PowerMock.createMock(ServiceLoader.class);

        EasyMock.expect(ServiceLoader.load(WebEnvironment.class)).andReturn(serviceLoader);
        EasyMock.expect(serviceLoader.iterator()).andReturn(environmentList.iterator());

        EasyMock.replay(servletContext);
        PowerMock.replayAll();

        WebEnvironment resultEnvironment = new EnvironmentLoader().createEnvironment(servletContext);

        PowerMock.verifyAll();
        EasyMock.verify(servletContext);

        assertThat(resultEnvironment, instanceOf(WebEnvironmentStub.class));
        WebEnvironmentStub environmentStub = (WebEnvironmentStub) resultEnvironment;

        assertThat(environmentStub.getServletContext(), sameInstance(servletContext));
    }

    @Test()
    public void multipleServiceTest() throws Exception {

        List<WebEnvironmentStub> environmentList = Arrays.asList(new WebEnvironmentStub(), new WebEnvironmentStub());

        ServletContext servletContext = EasyMock.mock(ServletContext.class);
        expect(servletContext.getInitParameter("shiroEnvironmentClass")).andReturn(null);

        PowerMock.mockStaticPartialStrict(ServiceLoader.class, "load");

        final ServiceLoader serviceLoader = PowerMock.createMock(ServiceLoader.class);

        EasyMock.expect(ServiceLoader.load(WebEnvironment.class)).andReturn(serviceLoader);
        EasyMock.expect(serviceLoader.iterator()).andReturn(environmentList.iterator());

        EasyMock.replay(servletContext);
        PowerMock.replayAll();

        try {
            new EnvironmentLoader().createEnvironment(servletContext);
            Assert.fail("Expected ConfigurationException to be thrown");
        }
        catch (ConfigurationException e) {
            assertThat(e.getMessage(), stringContainsInOrder("zero or exactly one", "shiroEnvironmentClass"));
        }

        PowerMock.verifyAll();
        EasyMock.verify(servletContext);
    }

    @Test()
    public void loadFromInitParamTest() throws Exception {

        ServletContext servletContext = EasyMock.mock(ServletContext.class);
        expect(servletContext.getInitParameter("shiroEnvironmentClass")).andReturn(WebEnvironmentStub.class.getName());
        expect(servletContext.getInitParameter("shiroConfigLocations")).andReturn(null);

        PowerMock.mockStaticPartialStrict(ServiceLoader.class, "load");

        EasyMock.replay(servletContext);
        PowerMock.replayAll();

        WebEnvironment resultEnvironment = new EnvironmentLoader().createEnvironment(servletContext);

        PowerMock.verifyAll();
        EasyMock.verify(servletContext);

        assertThat(resultEnvironment, instanceOf(WebEnvironmentStub.class));
        WebEnvironmentStub environmentStub = (WebEnvironmentStub) resultEnvironment;

        assertThat(environmentStub.getServletContext(), sameInstance(servletContext));
    }

}
