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

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertEquals(Status.UNAUTHORIZED.getStatusCode(), usersResponse.getStatus());
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
        assertEquals(Status.OK.getStatusCode(), usersResponse.getStatus());
        final Stormtrooper[] stormtroopers = usersResponse.readEntity(Stormtrooper[].class);
        assertEquals(50, stormtroopers.length);
        Arrays.stream(stormtroopers).forEach(stormtrooper
                -> assertTrue(stormtrooper.getStormtrooperId().getValue().startsWith("u")));
    }

}

