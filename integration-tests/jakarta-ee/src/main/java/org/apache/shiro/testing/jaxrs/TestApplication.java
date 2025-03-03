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

import java.util.List;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Destroyed;
import jakarta.enterprise.context.Initialized;
import jakarta.enterprise.event.Observes;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import lombok.Getter;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.testing.jakarta.ee.PropertyPrincipal;

@ApplicationPath("/")
@ApplicationScoped
public class TestApplication extends Application {
    private @Getter DefaultSecurityManager securityManager;

    void configureSecurityManager(@Observes @Initialized(ApplicationScoped.class) Object nothing) {
        var realm = new SimpleAccountRealm("testRealm") {
            @Override
            public void addAccount(String username, String password) {
                SimpleAccount account = new SimpleAccount(new SimplePrincipalCollection(
                        List.of(username, new PropertyPrincipal(username)), getName()), password);
                add(account);
            }
        };
        securityManager = new DefaultSecurityManager(realm);
        realm.addAccount("powerful", "awesome", "admin");
        realm.addAccount("regular", "meh", "user");
        realm.addAccount("user", "password");
    }

    void destroySecurityManager(@Observes @Destroyed(ApplicationScoped.class) Object nothing) {
        securityManager.destroy();
    }
}
