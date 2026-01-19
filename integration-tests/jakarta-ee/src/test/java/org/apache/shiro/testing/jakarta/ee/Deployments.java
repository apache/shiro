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
package org.apache.shiro.testing.jakarta.ee;

import static com.flowlogix.util.ShrinkWrapManipulator.Action;
import static com.flowlogix.util.ShrinkWrapManipulator.getContextParamValue;

import java.util.List;

import org.apache.shiro.testing.cdi.ComponentInjectionIT;

import static org.apache.shiro.ee.util.JakartaTransformer.jakartify;
import static org.apache.shiro.testing.cdi.ComponentInjectionIT.TESTABLE_MODE;
import static org.apache.shiro.testing.jakarta.ee.ShiroAuthFormsIT.DEPLOYMENT_DEV_MODE;
import static org.apache.shiro.testing.jakarta.ee.ShiroAuthFormsIT.DEPLOYMENT_PROD_MODE;

import org.eu.ingwar.tools.arquillian.extension.suite.annotations.ArquillianSuiteDeployment;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.spec.WebArchive;

/**
 * Arquillian Suite deployments
 */
@ArquillianSuiteDeployment
@SuppressWarnings("HideUtilityClassConstructor")
public class Deployments {
    static final String INTEGRATION_TEST_MODE_PROPERTY = "integration.test.mode";
    static final String CLIENT_STATE_SAVING = "clientStateSaving";
    static final String SHIRO_NATIVE_SESSIONS = "shiroNativeSessions";
    static final String SHIRO_EE_DISABLED = "disableShiroEE";
    @SuppressWarnings("ConstantName")
    static final List<Action> standardActions = initializeStandardActions();

    static boolean isClientStateSavingIntegrationTest() {
        return CLIENT_STATE_SAVING.equals(System.getProperty(INTEGRATION_TEST_MODE_PROPERTY));
    }

    static boolean isShiroNativeSessionsIntegrationTest() {
        return SHIRO_NATIVE_SESSIONS.equals(System.getProperty(INTEGRATION_TEST_MODE_PROPERTY));
    }

    @Deployment(testable = false, name = DEPLOYMENT_DEV_MODE)
    public static WebArchive createDeployment() {
        return ShiroAuthFormsIT.createDeploymentDev("ShiroSuiteTest-ui.war");
    }

    @Deployment(testable = false, name = DEPLOYMENT_PROD_MODE)
    public static WebArchive createDeploymentProd() {
        return ShiroAuthFormsIT.createDeploymentProd();
    }

    @Deployment(name = TESTABLE_MODE)
    public static WebArchive createNonUIDeployment() {
        return ComponentInjectionIT.createDeployment("ShiroSuiteTest.war");
    }

    private static List<Action> initializeStandardActions() {
        switch (System.getProperty(INTEGRATION_TEST_MODE_PROPERTY, "none")) {
            case CLIENT_STATE_SAVING:
                return List.of(new Action(getContextParamValue(jakartify("javax.faces.STATE_SAVING_METHOD")),
                        node -> node.setTextContent("client")));
            case SHIRO_NATIVE_SESSIONS:
                return List.of(new Action(getContextParamValue("shiroConfigLocations"),
                        node -> node.setTextContent(node.getTextContent()
                                + ",classpath:META-INF/shiro-native-sessions.ini")));
            case SHIRO_EE_DISABLED:
                return List.of(new Action(getContextParamValue("org.apache.shiro.ee.disabled"),
                        node -> node.setTextContent("true"), true));
            default:
                return List.of();
        }
    }
}
