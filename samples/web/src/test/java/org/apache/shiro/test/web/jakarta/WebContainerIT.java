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
import org.junit.jupiter.api.Test;

import java.net.URI;

import static jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;
import static jakarta.ws.rs.core.MediaType.TEXT_HTML_TYPE;
import static org.assertj.core.api.Assertions.assertThat;

public class WebContainerIT extends JakartaAbstractContainerIT {

    @SuppressWarnings("checkstyle:MagicNumber")
    @Test
    public void logIn() {
        try (Client client = ClientBuilder.newClient()) {
            Cookie jsessionid;
            try (Response loginPage = client.target(getBaseUri())
                    .path("/login.jsp")
                    .request(TEXT_HTML_TYPE)
                    .get()) {
                jsessionid = getSessionCookie(loginPage);
                assertThat(loginPage.readEntity(String.class)).contains("loginform");
            }

            assertThat(jsessionid).isNotNull();
            URI location;
            try (Response loginAction = client.target(getBaseUri())
                    .path("/login.jsp")
                    .request(APPLICATION_FORM_URLENCODED)
                    .cookie(jsessionid)
                    .post(Entity.entity("username=root&password=secret&submit=Login", APPLICATION_FORM_URLENCODED))) {
                jsessionid = getSessionCookie(loginAction);
                assertThat(loginAction.getStatus()).isEqualTo(302);
                location = loginAction.getLocation();
            }

            assertThat(location).isNotNull();
            final String loggedPage = client.target(getBaseUri())
                    .path(location.getPath())
                    .request(APPLICATION_FORM_URLENCODED)
                    .cookie(jsessionid)
                    .get(String.class);
            assertThat(loggedPage).contains("Hi root!");
        }
    }

    private static Cookie getSessionCookie(Response response) {
        return new Cookie.Builder("JSESSIONID")
                .value(response.getMetadata().get("Set-Cookie")
                        .stream().map(String.class::cast)
                        .filter(cookie -> cookie.startsWith("JSESSIONID="))
                        .filter(cookie -> !cookie.contains("deleteMe"))
                        .findAny().get().split(";")[0].split("=")[1]).build();
    }
}
