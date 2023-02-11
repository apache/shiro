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

import java.util.function.Supplier;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.subject.Subject;

@Path("whoami")
public class WhoamiResource {
    @Inject
    Subject subject;
    @Inject
    WhoamiBean whoamiBean;
    @Inject
    RolesAllowedBean rolesAllowedBean;

    @GET
    @Path("whoami")
    @Produces(APPLICATION_JSON)
    public JsonPojo whoami(@QueryParam("user") String user, @QueryParam("password") String password) {
        return check(whoamiBean::whoami, whoamiBean::noUser, user, password);
    }

    @GET
    @Path("rolesAllowed")
    @Produces(APPLICATION_JSON)
    public Response rolesAllowed(@QueryParam("user") String user, @QueryParam("password") String password) {
        return check(rolesAllowedBean::userRole, () -> Response.status(Status.UNAUTHORIZED).build(), user, password);
    }

    @GET
    @Path("otherRolesAllowed")
    @Produces(APPLICATION_JSON)
    public Response otherRolesAllowed(@QueryParam("user") String user, @QueryParam("password") String password) {
        return check(rolesAllowedBean::userAndOtherRole, () -> Response.status(Status.UNAUTHORIZED).build(), user, password);
    }

    @GET
    @Path("deny")
    @Produces(APPLICATION_JSON)
    public Response deny(@QueryParam("user") String user, @QueryParam("password") String password) {
        return check(rolesAllowedBean::deny, () -> Response.status(Status.UNAUTHORIZED).build(), user, password);
    }

    @GET
    @Path("permit")
    @Produces(APPLICATION_JSON)
    public Response permit(@QueryParam("user") String user, @QueryParam("password") String password) {
        return check(rolesAllowedBean::permit, rolesAllowedBean::permit, user, password);
    }

    private <T> T check(Supplier<T> happy, Supplier<T> sad, String user, String password) {
        try {
            subject.login(new UsernamePasswordToken(user, password));
            return happy.get();
        } catch (ShiroException e) {
            return sad.get();
        } finally {
            subject.logout();
        }
    }
}
