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

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.subject.Subject;

@Path("whoami")
public class WhoamiResource {
    @Inject
    Subject subject;
    @Inject
    WhoamiBean bean;

    @GET
    @Produces(APPLICATION_JSON)
    public JsonPojo whoami(@QueryParam("user") String user, @QueryParam("password") String password) {
        try {
            subject.login(new UsernamePasswordToken(user, password));
            return bean.whoami();
        } catch (ShiroException e) {
            return bean.noUser();
        } finally {
            subject.logout();
        }
    }
}
