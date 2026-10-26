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
package org.apache.shiro.ee.filters;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import jakarta.faces.application.ViewHandler;
import jakarta.faces.component.UIViewRoot;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.apache.shiro.ee.filters.FormResubmitSupport.AjaxReplay;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.omnifaces.util.ComponentsLocal;

import static jakarta.faces.application.StateManager.STATE_SAVING_METHOD_PARAM_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FormResubmitViewHandlerTest {
    private static final String VIEW_ID = "/form.xhtml";
    @Mock
    private FacesContext context;
    @Mock
    private ExternalContext externalContext;
    @Mock
    private ServletContext servletContext;
    @Mock
    private HttpServletRequest request;
    @Mock
    private ViewHandler wrapped;
    @Mock
    private UIViewRoot view;
    @Mock
    private MockedStatic<ComponentsLocal> components;

    private FormResubmitViewHandler handler;

    @BeforeEach
    void setUp() {
        handler = new FormResubmitViewHandler(wrapped);
        lenient().when(context.getExternalContext()).thenReturn(externalContext);
        lenient().when(externalContext.getRequest()).thenReturn(request);
        lenient().when(externalContext.getContext()).thenReturn(servletContext);
    }

    private void replay() {
        when(context.isPostback()).thenReturn(true);
        when(request.getAttributeNames()).thenReturn(Collections.emptyEnumeration());
        var replay = new FormResubmitRequest(request, Map.of(), AjaxReplay.FULL_PAGE);
        when(externalContext.getRequest()).thenReturn(new HttpServletRequestWrapper(replay));
    }

    @Test
    void existingViewIsRestoredNormally() {
        when(wrapped.restoreView(context, VIEW_ID)).thenReturn(view);
        assertThat(handler.restoreView(context, VIEW_ID)).isSameAs(view);
        components.verifyNoInteractions();
    }

    @Test
    void expiredReplayUsesOmniFacesViewBuilder() throws IOException {
        replay();
        components.when(() -> ComponentsLocal.buildView(context, VIEW_ID)).thenReturn(view);
        assertThat(handler.restoreView(context, VIEW_ID)).isSameAs(view);
        components.verify(() -> ComponentsLocal.buildView(context, VIEW_ID));
    }

    @Test
    void ordinaryExpiredPostbackIsNotRebuilt() {
        when(context.isPostback()).thenReturn(true);
        assertThat(handler.restoreView(context, VIEW_ID)).isNull();
        components.verifyNoInteractions();
    }

    @Test
    void initialRequestIsNotRebuilt() {
        assertThat(handler.restoreView(context, VIEW_ID)).isNull();
        components.verifyNoInteractions();
    }

    @Test
    void clientSideStateIsNotRebuilt() {
        replay();
        when(servletContext.getInitParameter(STATE_SAVING_METHOD_PARAM_NAME)).thenReturn("client");
        assertThat(handler.restoreView(context, VIEW_ID)).isNull();
        components.verifyNoInteractions();
    }

    @Test
    void buildFailurePropagatesToReplayFallback() throws IOException {
        replay();
        var failure = new IOException("Cannot build view");
        components.when(() -> ComponentsLocal.buildView(context, VIEW_ID)).thenThrow(failure);
        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> handler.restoreView(context, VIEW_ID)).isSameAs(failure);
    }
}
