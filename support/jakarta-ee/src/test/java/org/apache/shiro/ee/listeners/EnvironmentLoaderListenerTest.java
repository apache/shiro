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
package org.apache.shiro.ee.listeners;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.SessionCookieConfig;
import org.apache.shiro.web.env.WebEnvironment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.omnifaces.util.Faces;

import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.SHIRO_EE_DISABLE_SECURE_SESSION_COOKIE_PARAM;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.SHIRO_EE_SESSION_TRACKING_CONFIGURATION_DISABLED_PARAM;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EnvironmentLoaderListenerTest {
    @Mock
    private ServletContext context;
    @Mock
    private SessionCookieConfig cookieConfig;
    @Mock
    private MockedStatic<Faces> faces;

    private final EnvironmentLoaderListener listener = new EnvironmentLoaderListener() {
        @Override
        public WebEnvironment initEnvironment(ServletContext servletContext) {
            return null;
        }
    };

    @BeforeEach
    void setUp() {
        lenient().when(context.getInitParameter(SHIRO_EE_SESSION_TRACKING_CONFIGURATION_DISABLED_PARAM)).thenReturn("true");
    }

    @Test
    void productionEnforcesSecureCookieByDefault() {
        faces.when(Faces::hasContext).thenReturn(true);
        faces.when(Faces::isDevelopment).thenReturn(false);
        assertSecureCookieEnforced();
    }

    @Test
    void developmentDoesNotEnforceSecureCookieByDefault() {
        faces.when(Faces::hasContext).thenReturn(true);
        faces.when(Faces::isDevelopment).thenReturn(true);

        assertSecureCookieNotEnforced();
    }

    @Test
    void noFacesContextEnforcesSecureCookieByDefault() {
        faces.when(Faces::hasContext).thenReturn(false);
        assertSecureCookieEnforced();
        faces.verify(Faces::isDevelopment, never());
    }

    @Test
    void productionHonorsOptOut() {
        lenient().when(context.getInitParameter(SHIRO_EE_DISABLE_SECURE_SESSION_COOKIE_PARAM)).thenReturn("true");
        faces.when(Faces::isDevelopment).thenReturn(false);

        assertSecureCookieNotEnforced();
        faces.verifyNoInteractions();
    }

    private void assertSecureCookieEnforced() {
        when(context.getSessionCookieConfig()).thenReturn(cookieConfig);
        listener.contextInitialized(new ServletContextEvent(context));
        verify(cookieConfig).setSecure(true);
    }

    private void assertSecureCookieNotEnforced() {
        listener.contextInitialized(new ServletContextEvent(context));
        verify(context, never()).getSessionCookieConfig();
    }
}
