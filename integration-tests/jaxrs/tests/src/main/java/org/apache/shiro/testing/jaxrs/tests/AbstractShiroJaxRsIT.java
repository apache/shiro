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

package org.apache.shiro.testing.jaxrs.tests;

import org.apache.johnzon.jaxrs.jsonb.jaxrs.JsonbJaxrsProvider;
import org.apache.shiro.testing.jaxrs.app.json.JsonbConfigProvider;
import org.apache.shiro.testing.jaxrs.app.model.Stormtrooper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class AbstractShiroJaxRsIT {

    final Client client = ClientBuilder.newClient()
            .register(new JsonbConfigProvider())
            .register(new JsonbJaxrsProvider<>());

    protected abstract URI getBaseUri();

    @BeforeEach
    public void logOut() {
    }


    @Test
    public void testGetUsersUnauthenticated() {
        final WebTarget usersTarget = client.target(getBaseUri()).path("troopers");
        final Response usersResponse = usersTarget.request(MediaType.APPLICATION_JSON_TYPE)
                .buildGet()
                .invoke();
        assertThat(usersResponse.getStatus()).isEqualTo(Status.UNAUTHORIZED.getStatusCode());
    }

    @SuppressWarnings({"checkstyle:MagicNumber"})
    @Test
    public void testGetUsersBasicAuthenticated() {
        final WebTarget usersTarget = client.target(getBaseUri()).path("troopers");
        final String basicToken = Base64.getEncoder().encodeToString("root:secret".getBytes(StandardCharsets.UTF_8));
        final Response usersResponse = usersTarget.request(MediaType.APPLICATION_JSON_TYPE)
                .header("Authorization", "Basic " + basicToken)
                .buildGet()
                .invoke();
        assertThat(usersResponse.getStatus()).isEqualTo(Status.OK.getStatusCode());
        final Stormtrooper[] stormtroopers = usersResponse.readEntity(Stormtrooper[].class);
        assertThat(stormtroopers.length).isEqualTo(50);
        Arrays.stream(stormtroopers).forEach(stormtrooper
                -> assertThat(stormtrooper.getStormtrooperId().getValue().startsWith("u")).isTrue());
    }
}
