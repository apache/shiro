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

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.subject.Subject;

@ApplicationScoped
public class WhoamiBean {
    @Inject
    Subject subject;

    @RequiresUser
    JsonPojo whoami() {
        return JsonPojo.builder().userId(subject.getPrincipal().toString()).build();
    }

    JsonPojo noUser() {
        return JsonPojo.builder().userId("unauthenticated").build();
    }
}
