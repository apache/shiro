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
import static org.apache.shiro.ee.filters.FormResubmitSupport.REBUILD_EXPIRED_VIEW;
import jakarta.faces.application.ViewHandler;
import jakarta.faces.application.ViewHandlerWrapper;
import jakarta.faces.component.UIViewRoot;
import jakarta.faces.context.FacesContext;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitAjaxRenderAllDisabled;
import lombok.SneakyThrows;
import org.omnifaces.util.ComponentsLocal;
import org.omnifaces.util.FacesLocal;

/**
 * Rebuilds expired server-side views only for marked or replayed Shiro form submissions.
 */
public class FormResubmitViewHandler extends ViewHandlerWrapper {
    public FormResubmitViewHandler(ViewHandler wrapped) {
        super(wrapped);
    }

    @Override
    @SneakyThrows(IOException.class)
    public UIViewRoot restoreView(FacesContext context, String viewId) {
        var view = super.restoreView(context, viewId);
        var request = FacesLocal.getRequest(context);
        boolean rebuildExpiredView = Boolean.TRUE.equals(request.getAttribute(REBUILD_EXPIRED_VIEW));
        if (view == null && context.isPostback() && (FormResubmitRequest.isResubmit(request) || rebuildExpiredView)
                && !FormResubmitSupport.isJSFClientStateSavingMethod(FacesLocal.getServletContext(context))) {
            if (rebuildExpiredView && context.getPartialViewContext().isAjaxRequest()
                    && !isFormResubmitAjaxRenderAllDisabled(FacesLocal.getServletContext(context))) {
                context.getPartialViewContext().setRenderAll(true);
            }
            boolean processingEvents = context.isProcessingEvents();
            context.setProcessingEvents(true);
            try {
                return ComponentsLocal.buildView(context, viewId);
            } finally {
                context.setProcessingEvents(processingEvents);
            }
        }
        return view;
    }
}
