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
package org.apache.shiro.samples;

import org.apache.shiro.testing.web.AbstractContainerIT;
import org.junit.Test;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Response;
import java.net.URI;

import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static javax.ws.rs.core.MediaType.TEXT_HTML_TYPE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class ContainerIntegrationIT extends AbstractContainerIT {

    @Test
    public void logIn() {
        final Client client = ClientBuilder.newClient();

        try {
            Cookie jsessionid;
            try (final Response loginPage = client.target(getBaseUri())
                    .path("/s/login")
                    .request(TEXT_HTML_TYPE)
                    .get()) {
                jsessionid = new Cookie("JSESSIONID", loginPage.getMetadata().get("Set-Cookie").get(0).toString().split(";")[0].split("=")[1]);
                assertTrue(loginPage.readEntity(String.class).contains("loginCommand"));
            }

            assertNotNull(jsessionid);
            URI location;
            try (final Response loginAction = client.target(getBaseUri())
                    .path("/s/login")
                    .request(APPLICATION_FORM_URLENCODED)
                    .cookie(jsessionid)
                    .post(Entity.entity("username=admin&password=admin&submit=Login", APPLICATION_FORM_URLENCODED))) {
                assertEquals(302, loginAction.getStatus());
                location = loginAction.getLocation();
            }

            assertNotNull(location);
            final String loggedPage = client.target(getBaseUri())
                    .path(location.getPath())
                    .request(APPLICATION_FORM_URLENCODED)
                    .cookie(jsessionid)
                    .get(String.class);

            assertTrue(loggedPage.contains("Logged in as admin"));
        } finally {
            client.close();
        }
    }
}
