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
 * This abstract class represents a common interface for all integration test
 * mode actions.
 * Subclasses must implement the {@code getActions} method that returns a list
 * of actions to be performed
 * based on the integration test mode.
 */
abstract class IntegrationTestModeAction {

    /**
     * Returns a list of actions to be performed based on the integration test mode.
     *
     * @param contextParamValue the value of the context parameter for the
     *                          integration test mode
     * @return a list of actions to be performed
     */
    public abstract List<Action> getActions(String contextParamValue);
}

/**
 * This class represents an integration test mode action for client-side state
 * saving.
 * It returns a list of actions that set the state saving method to "client".
 */

class ClientStateSavingAction extends IntegrationTestModeAction {

    /**
     * Returns a list of actions that set the state saving method to "client".
     *
     * @param contextParamValue the value of the context parameter for the
     *                          integration test mode
     * @return a list of actions to be performed
     */
    @Override
    public List<Action> getActions(String contextParamValue) {
        return List.of(new Action(getContextParamValue(jakartify("javax.faces.STATE_SAVING_METHOD")),
                node -> node.setTextContent("client")));
    }
}

/**
 * This class represents an integration test mode action for Shiro native
 * sessions.
 * It returns a list of actions that add the Shiro native sessions configuration
 * to the classpath.
 */
class ShiroNativeSessionsAction extends IntegrationTestModeAction {

    /**
     * Returns a list of actions that add the Shiro native sessions configuration to
     * the classpath.
     *
     * @param contextParamValue the value of the context parameter for the
     *                          integration test mode
     * @return a list of actions to be performed
     */
    @Override
    public List<Action> getActions(String contextParamValue) {
        return List.of(new Action(getContextParamValue("shiroConfigLocations"),
                node -> node.setTextContent(node.getTextContent()
                        + ",classpath:META-INF/shiro-native-sessions.ini")));
    }
}

/**
 * This class represents an integration test mode action for disabling Shiro EE
 * features.
 * It returns a list of actions that disable the Shiro EE features.
 */
class ShiroEEDisabledAction extends IntegrationTestModeAction {

    /**
     * Returns a list of actions that disable the Shiro EE features.
     *
     * @param contextParamValue the value of the context parameter for the
     *                          integration test mode
     * @return a list of actions to be performed
     */
    @Override
    public List<Action> getActions(String contextParamValue) {
        return List.of(new Action(getContextParamValue("org.apache.shiro.ee.disabled"),
                node -> node.setTextContent("true"), true));
    }
}

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
        IntegrationTestModeAction action;
        String integrationTestMode = System.getProperty(INTEGRATION_TEST_MODE_PROPERTY, "none");
        switch (integrationTestMode) {
            case CLIENT_STATE_SAVING:
                action = new ClientStateSavingAction();
                return action.getActions(getContextParamValue(integrationTestMode));
            case SHIRO_NATIVE_SESSIONS:
                action = new ShiroNativeSessionsAction();
                return action.getActions(getContextParamValue(integrationTestMode));
            case SHIRO_EE_DISABLED:
                action = new ShiroEEDisabledAction();
                return action.getActions(getContextParamValue(integrationTestMode));
            default:
                return List.of();
        }
    }
}
