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

import javax.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.UsernamePasswordToken;
import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.testing.jaxrs.NoIniJaxRsIT;
import org.apache.shiro.util.ThreadContext;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.jupiter.api.AfterAll;
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
        var realm = new SimpleAccountRealm();
        var sm = new DefaultSecurityManager(realm);
        realm.addAccount("user", "password");
        ThreadContext.bind(sm);
    }

    @AfterEach
    void unbind() {
        ThreadContext.unbindSecurityManager();
    }

    @AfterAll
    static void cleanup() {
        ThreadContext.remove();
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void securityManagerInjection() {
        assertNotNull(injectedComponents.securityManager);
        assertNull(injectedComponents.securityManager.getSession(() -> null));
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void subjectInjection() {
        assertNotNull(injectedComponents.subject);
        assertNull(injectedComponents.subject.getPrincipal());
        assertFalse(injectedComponents.subject.isAuthenticated());
        UsernamePasswordToken token = new UsernamePasswordToken("user", "password");
        injectedComponents.subject.login(token);
        assertTrue(injectedComponents.subject.isAuthenticated());

        injectedComponents.subject.logout();
        assertFalse(injectedComponents.subject.isAuthenticated());
    }

    @Test
    @OperateOnDeployment(TESTABLE_MODE)
    void sessionInjection() {
        assertNotNull(injectedComponents.session);
        assertNotNull(injectedComponents.noCreateionSession);
        injectedComponents.session.setAttribute("hello", "bye");
        assertEquals("bye", injectedComponents.session.getAttribute("hello"));
        assertEquals("bye", injectedComponents.noCreateionSession.getAttribute("hello"));
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
                .addPackages(true, "org.slf4j");
        log.debug("Archive contents for {}: {}", archive, webArchive.toString(true));
        return webArchive;
    }
}
