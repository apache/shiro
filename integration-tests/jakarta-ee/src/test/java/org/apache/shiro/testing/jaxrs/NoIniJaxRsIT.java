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
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.UriBuilder;
import org.apache.shiro.testing.cdi.ComponentInjectionIT;
import static org.apache.shiro.testing.cdi.ComponentInjectionIT.TESTABLE_MODE;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(ArquillianExtension.class)
public class NoIniJaxRsIT {
    @ArquillianResource
    private URL base;
    private WebTarget webTarget;
    private Client client;

    @BeforeEach
    void init() throws MalformedURLException {
        client = ClientBuilder.newClient();
        var uri = UriBuilder.fromUri(URI.create(new URL(base, "whoami").toExternalForm()))
                .queryParam("user", "powerful").queryParam("password", "awesome").build();
        webTarget = client.target(uri);
    }

    @AfterEach
    void destroy() {
        client.close();
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void whoami() {
        try {
            var pojo = webTarget.request().get().readEntity(JsonPojo.class);
            assertEquals("powerful", pojo.getUserId());
        } catch (JsonbException t) {
            fail(t.getMessage());
        }
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void unauthenticated() throws MalformedURLException {
        var target = client.target(URI.create(new URL(base, "whoami").toExternalForm()));
        var pojo = target.request().get().readEntity(JsonPojo.class);
        assertEquals("unauthenticated", pojo.getUserId());
    }

    @OperateOnDeployment(TESTABLE_MODE)
    public static WebArchive createDeployment() {
        return ComponentInjectionIT.createDeployment("no-ini-jaxrs.war");
    }
}
