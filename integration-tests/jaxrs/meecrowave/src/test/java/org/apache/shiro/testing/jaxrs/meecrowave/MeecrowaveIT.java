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

package org.apache.shiro.testing.jaxrs.meecrowave;

import org.apache.meecrowave.Meecrowave;
import org.apache.meecrowave.junit5.MeecrowaveConfig;
import org.apache.meecrowave.testing.ConfigurationInject;
import org.apache.shiro.testing.jaxrs.tests.AbstractShiroJaxRsIT;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;

@MeecrowaveConfig(jaxrsLogProviders = true)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class MeecrowaveIT extends AbstractShiroJaxRsIT {

    @ConfigurationInject
    private Meecrowave.Builder config;

    @Override
    protected URI getBaseUri() {
        return URI.create("http://localhost:" + config.getHttpPort() + "/api");
    }

}
