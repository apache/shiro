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
package org.apache.shiro.ee.cdi;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.enterprise.context.SessionScoped;
import jakarta.enterprise.context.spi.CreationalContext;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.faces.view.ViewScoped;
import java.io.Serializable;
import java.lang.annotation.Annotation;

import static org.apache.shiro.ee.cdi.ShiroScopeContext.isWebContainerSessions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Shiro Scope override tests
 */
@ExtendWith(MockitoExtension.class)
public class ShiroScopeContextTest {
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Bean<ViewScoped> contextual;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private CreationalContext<ViewScoped> creationalContext;

    private MockedStatic<SecurityUtils> secMock;
    private MyBean bean;
    private ShiroScopeContext ctx;

    private static final class MyBean implements ViewScoped, Serializable {
        private static final long serialVersionUID = 1L;

        @Override
        public Class<? extends Annotation> annotationType() {
            throw new UnsupportedOperationException("Not supported");
        }
    }

    @BeforeEach
    void setup() {
        bean = new MyBean();
        ctx = new ShiroScopeContext(ViewScoped.class, SessionScoped.class);
        secMock = mockStatic(SecurityUtils.class, Answers.RETURNS_DEEP_STUBS);
        lenient().when(contextual.getBeanClass()).thenAnswer((inv) -> MyBean.class);
    }

    @AfterEach
    void teardown() {
        secMock.close();
    }

    @Test
    void basics() {
        assertTrue(ctx.isActive());
        assertEquals(ViewScoped.class, ctx.getScope());
    }

    @Test
    void webSessionsBasic() {
        setupWebSessions();
        assertTrue(isWebContainerSessions(SecurityUtils.getSecurityManager()));
    }

    @Test
    void webSessionsGet() {
        setupWebSessions();
        try (var cdim = mockStatic(CDI.class, Answers.RETURNS_DEEP_STUBS)) {
            when(CDI.current().getBeanManager().getContext(SessionScoped.class).get(contextual)).thenReturn(bean);
            assertEquals(bean, ctx.get(contextual));
            assertNull(ctx.get(null));
            verify(CDI.current().getBeanManager(), atLeast(2)).getContext(any());
        }
    }

    @Test
    void webSessionsCreate() {
        setupWebSessions();
        try (var cdim = mockStatic(CDI.class, Answers.RETURNS_DEEP_STUBS)) {
            when(CDI.current().getBeanManager().getContext(SessionScoped.class)
                    .get(contextual, creationalContext)).thenReturn(bean);
            assertEquals(bean, ctx.get(contextual, creationalContext));
            assertNull(ctx.get(null));
            verify(CDI.current().getBeanManager(), atLeast(2)).getContext(any());
        }
    }


    private void setupWebSessions() {
        when(SecurityUtils.getSecurityManager()).thenReturn(mock(WebSecurityManager.class));
        WebSecurityManager wsm = (WebSecurityManager) SecurityUtils.getSecurityManager();
        when(wsm.isHttpSessionMode()).thenReturn(true);
    }
}
