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
import javax.enterprise.context.Destroyed;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Observes;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;

@ApplicationPath("/")
@ApplicationScoped
public class TestApplication extends Application {
    void configureSecurityManager(@Observes @Initialized(ApplicationScoped.class) Object nothing) {
        var realm = new SimpleAccountRealm();
        var sm = new DefaultSecurityManager(realm);
        realm.addAccount("powerful", "awesome");
        SecurityUtils.setSecurityManager(sm);
    }

    void destroySecurityManager(@Observes @Destroyed(ApplicationScoped.class) Object nothing) {
        SecurityUtils.setSecurityManager(null);
    }
}
