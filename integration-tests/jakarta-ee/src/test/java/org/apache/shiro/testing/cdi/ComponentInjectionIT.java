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

import java.util.List;
import javax.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.UsernamePasswordToken;
import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.testing.jakarta.ee.PropertyPrincipal;
import org.apache.shiro.testing.jaxrs.NoIniJaxRsIT;
import org.apache.shiro.util.ThreadContext;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests @Injecting Subject, Session and SecurityManager with CDI
 */
@ExtendWith(ArquillianExtension.class)
@Execution(ExecutionMode.SAME_THREAD)
@Slf4j
public class ComponentInjectionIT {
    @SuppressWarnings("JavadocVariable")
    public static final String TESTABLE_MODE = "TestableMode";

    @Inject
    ComponentInjectionBean injectedComponents;

    @BeforeEach
    void bind() {
        var realm = new SimpleAccountRealm("testRealm") {
            @Override
            public void addAccount(String username, String password) {
                SimpleAccount account = new SimpleAccount(new SimplePrincipalCollection(
                        List.of(username, new PropertyPrincipal(username)), getName()), password);
                add(account);
            }
        };
        var sm = new DefaultSecurityManager(realm);
        realm.addAccount("user", "password");
        ThreadContext.bind(sm);
    }

    @AfterEach
    void unbind() {
        ThreadContext.unbindSecurityManager();
        ThreadContext.unbindSubject();
        ThreadContext.remove();
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void securityManagerInjection() {
        assertNotNull(injectedComponents.getSecurityManager());
        assertNull(injectedComponents.getSecurityManager().getSession(() -> null));
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void subjectInjection() {
        assertNotNull(injectedComponents.getSubject());
        assertNull(injectedComponents.getSubject().getPrincipal());
        assertFalse(injectedComponents.getSubject().isAuthenticated());
        UsernamePasswordToken token = new UsernamePasswordToken("user", "password");
        injectedComponents.getSubject().login(token);
        assertTrue(injectedComponents.getSubject().isAuthenticated());

        injectedComponents.getSubject().logout();
        assertFalse(injectedComponents.getSubject().isAuthenticated());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void sessionInjection() {
        assertNotNull(injectedComponents.getSession());
        assertNotNull(injectedComponents.getNoCreateionSession());
        injectedComponents.getSession().setAttribute("hello", "bye");
        assertEquals("bye", injectedComponents.getSession().getAttribute("hello"));
        assertEquals("bye", injectedComponents.getNoCreateionSession().getAttribute("hello"));
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void principalInjection() {
        SecurityUtils.getSubject().login(new UsernamePasswordToken("user", "password"));
        assertNotNull(injectedComponents.getPropertyPincipal());
        assertEquals("user", injectedComponents.getPropertyPincipal().orElseThrow().getUserName());
        injectedComponents.getSubject().logout();
    }

    @Deployment(name = TESTABLE_MODE)
    public static WebArchive createDeployment() {
        return createDeployment("security-manager-injection.war");
    }

    public static WebArchive createDeployment(String archive) {
        var webArchive = ShrinkWrap.create(WebArchive.class, archive)
                .addAsResource("META-INF/beans.xml")
                .addAsResource(new StringAsset("org.apache.shiro.cdi.ShiroSecurityExtension"),
                        jakartify("META-INF/services/javax.enterprise.inject.spi.Extension"))
                .addPackages(true, "org.apache.shiro")
                .addPackages(true, "org.apache.commons")
                .deletePackages(true, "org.apache.shiro.testing")
                .deletePackages(true, "org.apache.shiro.ee")
                .addClass(ComponentInjectionIT.class)
                .addPackages(true, "org.apache.shiro.testing.jaxrs")
                .addPackage("org.apache.shiro.ee.util")
                .addClass(NoIniJaxRsIT.class)
                .addClass(PropertyPrincipal.class)
                .addClass(ComponentInjectionBean.class)
                .addPackages(true, "org.slf4j");
        log.debug("Archive contents for {}: {}", archive, webArchive.toString(true));
        return webArchive;
    }
}
