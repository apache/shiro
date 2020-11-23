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

package org.apache.shiro.web.it.loader;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.web.env.EnvironmentLoader;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletContext;
import java.io.InputStream;

import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecondaryWebEnvironmentTest {

    @Test
    @DisplayName("Try loading a WebEnvironment while two implementations are available.")
    public void multipleServiceTest() {
        InputStream resourceAsStream = getClass()
                .getResourceAsStream("/org/apache/shiro/web/env/EnvironmentLoaderServiceTest.ini");

        ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getResourceAsStream("/WEB-INF/shiro.ini")).then(args -> resourceAsStream);

        try {
            new EnvironmentLoader().initEnvironment(servletContext);
            Assertions.fail("Expected ConfigurationException to be thrown");
        } catch (ConfigurationException e) {
            MatcherAssert.assertThat(e.getMessage(), stringContainsInOrder("zero or exactly one", "shiroEnvironmentClass"));
        }
    }

}
