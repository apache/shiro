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
package org.apache.shiro.testing.cdi;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import lombok.Getter;
import org.apache.shiro.cdi.annotations.NoSessionCreation;
import org.apache.shiro.cdi.annotations.Principal;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.testing.jakarta.ee.PropertyPrincipal;

import java.util.function.Supplier;

@ApplicationScoped
@Getter
public class ComponentInjectionBean {
    @Inject
    SecurityManager securityManager;
    @Inject
    Subject subject;
    @Inject
    Session session;
    @Inject
    @NoSessionCreation
    Session noCreateionSession;
    @Inject
    @Principal
    Supplier<PropertyPrincipal> propertyPrincipal;
}
