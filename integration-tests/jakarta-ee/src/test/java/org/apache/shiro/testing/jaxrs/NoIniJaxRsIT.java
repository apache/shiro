/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.testing.jaxrs;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import javax.json.bind.JsonbException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;
import lombok.Builder;
import lombok.SneakyThrows;
import org.apache.shiro.testing.cdi.ComponentInjectionIT;
import static org.apache.shiro.testing.cdi.ComponentInjectionIT.TESTABLE_MODE;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(ArquillianExtension.class)
public class NoIniJaxRsIT {
    @Builder
    private static class Credentials {
        final boolean send;
        final String username;
        final String password;
    }

    @ArquillianResource
    private URL base;

    @SneakyThrows(MalformedURLException.class)
    WebTarget createWebTarget(String path, Credentials credentials) {
        var client = ClientBuilder.newClient();
        var uri = credentials.send ? UriBuilder.fromUri(URI.create(new URL(base, path).toExternalForm()))
                .queryParam("user", credentials.username).queryParam("password", credentials.password).build()
                : URI.create(new URL(base, path).toExternalForm());
        return client.target(uri);
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void whoami() {
        try {
            var pojo = createWebTarget("whoami/whoami", Credentials.builder()
                    .username("powerful").password("awesome").send(true).build())
                    .request().get().readEntity(JsonPojo.class);
            assertEquals("powerful", pojo.getUserId());
        } catch (JsonbException t) {
            fail(t.getMessage());
        }
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void unauthenticated() {
        var pojo = createWebTarget("whoami/whoami", Credentials.builder().send(false).build())
                .request().get().readEntity(JsonPojo.class);
        assertEquals("unauthenticated", pojo.getUserId());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void rolesAllowed() {
        assertEquals(Status.OK.getStatusCode(), createWebTarget("whoami/rolesAllowed",
                Credentials.builder().username("regular").password("meh").send(true).build())
                .request().get().getStatus());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void otherRolesAllowed() {
        assertEquals(Status.OK.getStatusCode(), createWebTarget("whoami/otherRolesAllowed",
                Credentials.builder().username("regular").password("meh").send(true).build())
                .request().get().getStatus());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void otherRolesNotAllowed() {
        assertEquals(Status.UNAUTHORIZED.getStatusCode(), createWebTarget("whoami/otherRolesAllowed",
                Credentials.builder().username("powerful").password("awesome").send(true).build())
                .request().get().getStatus());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void rolesNotAllowed() {
        assertEquals(Status.UNAUTHORIZED.getStatusCode(), createWebTarget("whoami/rolesAllowed",
                Credentials.builder().username("powerful").password("awesome").send(true).build())
                .request().get().getStatus());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void permit() {
        assertEquals(Status.OK.getStatusCode(), createWebTarget("whoami/permit",
                Credentials.builder().send(false).build())
                .request().get().getStatus());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void deny() {
        assertEquals(Status.UNAUTHORIZED.getStatusCode(), createWebTarget("whoami/rolesAllowed",
                Credentials.builder().username("powerful").password("awesome").send(true).build())
                .request().get().getStatus());
    }

    @Deployment(name = TESTABLE_MODE)
    public static WebArchive createDeployment() {
        return ComponentInjectionIT.createDeployment("no-ini-jaxrs.war");
    }
}
