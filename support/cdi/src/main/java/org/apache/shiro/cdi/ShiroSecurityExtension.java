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
package org.apache.shiro.cdi;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.inject.spi.WithAnnotations;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;

/**
 * Automatically apply Shiro security to all appropriate beans
 */
public class ShiroSecurityExtension implements Extension {
    @ShiroSecureAnnotation
    public static class ShiroSecureAnnotated { };

    public <T> void addSecurity(@Observes @WithAnnotations({
        RequiresAuthentication.class, RequiresGuest.class, RequiresPermissions.class,
        RequiresRoles.class, RequiresUser.class, RolesAllowed.class,
        PermitAll.class, DenyAll.class}) ProcessAnnotatedType<T> pat) {
        pat.setAnnotatedType(new AnnotatedTypeWrapper<>(pat.getAnnotatedType(),
                ShiroSecureAnnotated.class.getDeclaredAnnotations()[0]));
    }
}
