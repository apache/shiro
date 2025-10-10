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

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class RolesAllowedBean {
    @RolesAllowed("user")
    Response userRole() {
        return Response.ok().build();
    }

    @RolesAllowed({"user", "other"})
    Response userAndOtherRole() {
        return Response.ok().build();
    }

    @DenyAll
    Response deny() {
        return Response.ok().build();
    }

    @PermitAll
    Response permit() {
        return Response.ok().build();
    }
}
