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

import javax.servlet.ServletContext;
import java.util.Arrays;
import java.util.List;

import static org.easymock.EasyMock.expect;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.*;

/**
 * Tests for {@link EnvironmentLoader} that depend on PowerMock the stub out a ServiceLoader.
 */
public class EnvironmentLoaderServiceTest {

    @Test()
    public void singleServiceTest() throws Exception {

        ServletContext servletContext = EasyMock.mock(ServletContext.class);
        expect(servletContext.getInitParameter("shiroEnvironmentClass")).andReturn(null);
        expect(servletContext.getInitParameter("shiroConfigLocations")).andReturn(null);
        expect(servletContext.getResourceAsStream("/WEB-INF/shiro.ini")).andReturn(
                getClass().getResourceAsStream("/EmptyShiroIni.ini"));

        EasyMock.replay(servletContext);

        WebEnvironment resultEnvironment = new EnvironmentLoader().createEnvironment(servletContext);

        EasyMock.verify(servletContext);

        assertThat(resultEnvironment, instanceOf(IniWebEnvironment.class));
        IniWebEnvironment environmentStub = (IniWebEnvironment) resultEnvironment;

        assertThat(environmentStub.getServletContext(), sameInstance(servletContext));
    }

    @Test()
    public void multipleServiceTest() throws Exception {

        List<WebEnvironment> environmentList = Arrays.asList(new WebEnvironmentStub(), new WebEnvironmentStub());

        ServletContext servletContext = EasyMock.mock(ServletContext.class);
        expect(servletContext.getInitParameter(EnvironmentLoader.ENVIRONMENT_CLASS_PARAM)).andReturn(null);

        EasyMock.replay(servletContext);

        final EnvironmentLoader environmentLoader = EasyMock.createMockBuilder(EnvironmentLoader.class)
                .addMockedMethod("doLoadWebEnvironmentsFromServiceLoader")
                .createMock();
        EasyMock.expect(environmentLoader.doLoadWebEnvironmentsFromServiceLoader()).andReturn(environmentList.iterator());
        EasyMock.replay(environmentLoader);

        try {
            environmentLoader.createEnvironment(servletContext);
            Assert.fail("Expected ConfigurationException to be thrown");
        }
        catch (ConfigurationException e) {
            assertThat(e.getMessage(), stringContainsInOrder("zero or exactly one", "shiroEnvironmentClass"));
        }

        EasyMock.verify(servletContext);
        EasyMock.verify(environmentLoader);
    }

    @Test()
    public void loadFromInitParamTest() throws Exception {

        ServletContext servletContext = EasyMock.mock(ServletContext.class);
        expect(servletContext.getInitParameter(EnvironmentLoader.ENVIRONMENT_CLASS_PARAM)).andReturn(WebEnvironmentStub.class.getName());
        expect(servletContext.getInitParameter("shiroConfigLocations")).andReturn(null);

        EasyMock.replay(servletContext);

        WebEnvironment resultEnvironment = new EnvironmentLoader().createEnvironment(servletContext);

        EasyMock.verify(servletContext);

        assertThat(resultEnvironment, instanceOf(WebEnvironmentStub.class));
        WebEnvironmentStub environmentStub = (WebEnvironmentStub) resultEnvironment;

        assertThat(environmentStub.getServletContext(), sameInstance(servletContext));
    }

}
