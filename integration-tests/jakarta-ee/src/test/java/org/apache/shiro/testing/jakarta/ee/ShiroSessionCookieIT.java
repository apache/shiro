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
package org.apache.shiro.testing.jakarta.ee;

import static com.flowlogix.util.ShrinkWrapManipulator.getContextParamValue;
import static org.assertj.core.api.Assertions.assertThat;

import com.flowlogix.util.ShrinkWrapManipulator;
import com.flowlogix.util.ShrinkWrapManipulator.Action;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(ArquillianExtension.class)
public class ShiroSessionCookieIT {
    static final String SESSION_COOKIE_DEFAULT = "session-cookie-default";
    static final String SESSION_COOKIE_OPT_OUT = "session-cookie-opt-out";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    @ArquillianResource
    private URL baseUrl;

    @Test
    @OperateOnDeployment(SESSION_COOKIE_DEFAULT)
    void productionSessionCookieIsSecure() throws Exception {
        assertThat(sessionCookieIsSecure(baseUrl)).as("JSESSIONID has the Secure attribute by default").isTrue();
    }

    @Test
    @OperateOnDeployment(SESSION_COOKIE_OPT_OUT)
    void productionSessionCookieHonorsOptOut() throws Exception {
        assertThat(sessionCookieIsSecure(baseUrl)).as("JSESSIONID has the Secure attribute after opt-out").isFalse();
    }

    static WebArchive createDeployment(String name, boolean optOut) {
        var archive = ShiroAuthFormsIT.createDeploymentProd(name).addClass(CreateSessionServlet.class);
        // Keep these deployments on container sessions even in the suite's native session mode.
        var actions = new ArrayList<>(List.of(
                new Action(getContextParamValue("shiroConfigLocations"),
                        node -> node.setTextContent("classpath:META-INF/shiro.ini")),
                new Action(getContextParamValue("org.apache.shiro.ee.disabled"),
                        node -> node.setTextContent("false"))));
        if (optOut) {
            actions.add(new Action("/web-app", webApp -> {
                var document = webApp.getOwnerDocument();
                var contextParam = document.createElement("context-param");
                var paramName = document.createElement("param-name");
                paramName.setTextContent("org.apache.shiro.ee.secure-session-cookie.disabled");
                var paramValue = document.createElement("param-value");
                paramValue.setTextContent("true");
                contextParam.appendChild(paramName);
                contextParam.appendChild(paramValue);
                webApp.appendChild(contextParam);
            }));
        }
        new ShrinkWrapManipulator().webXmlXPath(archive, actions);
        return archive;
    }

    private static boolean sessionCookieIsSecure(URL baseUrl) throws Exception {
        var request = HttpRequest.newBuilder(baseUrl.toURI().resolve(CreateSessionServlet.PATH.substring(1)))
                .timeout(REQUEST_TIMEOUT)
                .build();
        var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(HttpServletResponse.SC_NO_CONTENT);
        var cookies = response.headers().allValues("Set-Cookie").stream()
                .filter(cookie -> cookie.startsWith("JSESSIONID="))
                .toList();
        assertThat(cookies).hasSize(1);
        return Arrays.stream(cookies.get(0).split(";")).skip(1)
                .map(String::trim)
                .anyMatch("Secure"::equalsIgnoreCase);
    }
}
