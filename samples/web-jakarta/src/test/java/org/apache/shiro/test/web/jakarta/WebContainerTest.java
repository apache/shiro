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
package org.apache.shiro.test.web.jakarta;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static jakarta.ws.rs.core.MediaType.TEXT_HTML_TYPE;

public class WebContainerTest extends JakartaAbstractContainerIT {

    @SuppressWarnings("checkstyle:MagicNumber")
    @Test
    public void logIn() {
        final Client client = ClientBuilder.newClient();

        try {
            Cookie jsessionid;
            try (Response loginPage = client.target(getBaseUri())
                    .path("/login.jsp")
                    .request(TEXT_HTML_TYPE)
                    .get()) {
                jsessionid = new Cookie("JSESSIONID",
                        loginPage.getMetadata().get("Set-Cookie").get(0).toString().split(";")[0].split("=")[1]);
                Assertions.assertTrue(loginPage.readEntity(String.class).contains("loginform"));
            }

            Assertions.assertNotNull(jsessionid);
            URI location;
            try (Response loginAction = client.target(getBaseUri())
                    .path("/login.jsp")
                    .request(APPLICATION_FORM_URLENCODED)
                    .cookie(jsessionid)
                    .post(Entity.entity("username=root&password=secret&submit=Login", APPLICATION_FORM_URLENCODED))) {
                Assertions.assertEquals(302, loginAction.getStatus());
                location = loginAction.getLocation();
            }

            Assertions.assertNotNull(location);
            final String loggedPage = client.target(getBaseUri())
                    .path(location.getPath())
                    .request(APPLICATION_FORM_URLENCODED)
                    .cookie(jsessionid)
                    .get(String.class);
            Assertions.assertTrue(loggedPage.contains("Hi root!"));
        } finally {
            client.close();
        }
    }
}
