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
package org.apache.shiro.ee.faces.tags;

import jakarta.el.ELException;
import jakarta.el.ValueExpression;
import jakarta.faces.FacesException;
import jakarta.faces.component.UIComponent;
import jakarta.faces.view.facelets.FaceletContext;
import jakarta.faces.view.facelets.TagAttribute;
import jakarta.faces.view.facelets.TagConfig;
import java.io.IOException;

/**
 * Base TagHandler for Tags that check for permissions.
 */
public abstract class PermissionTagHandler extends SecureTagHandler {
    private final TagAttribute name;

    public PermissionTagHandler(TagConfig config) {
        super(config);
        this.name = this.getRequiredAttribute("name");
    }

    private String getAttrValue(FaceletContext ctx, TagAttribute attr) {
        String value;
        if (attr.isLiteral()) {
            value = attr.getValue(ctx);
        } else {
            ValueExpression expression = attr.getValueExpression(ctx, String.class);
            value = (String) expression.getValue(ctx);
        }
        return value;
    }

    @Override
    public void apply(FaceletContext ctx, UIComponent parent)
            throws IOException, FacesException, ELException {
        String perm;
        perm = getAttrValue(ctx, name);
        if (showTagBody(perm)) {
            this.nextHandler.apply(ctx, parent);
        }
    }

    protected boolean isPermitted(String p) {
        return getSubject() != null && getSubject().isPermitted(p);
    }

    protected abstract boolean showTagBody(String p);
}
