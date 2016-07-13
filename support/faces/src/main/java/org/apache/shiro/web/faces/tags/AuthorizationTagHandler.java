/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.faces.tags;

import javax.el.ValueExpression;
import javax.faces.component.UIComponent;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagAttribute;
import javax.faces.view.facelets.TagConfig;

/**
 * Tag handler which shows or hides body content based on the current Subject's authorization state.  'Authorization
 * state' means whether or not they have or do not have a role or whether they are permitted to do something or not.
 *
 * @since 2.0
 */
public abstract class AuthorizationTagHandler extends SecureTagHandler {

    private final TagAttribute name;

    public AuthorizationTagHandler(TagConfig config) {
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
    protected boolean showTagBody(FaceletContext ctx, UIComponent parent) {
        String value = getAttrValue(ctx, name);
        return showTagBody(value);
    }
    
    protected boolean showTagBody(String nameAttributeValue) {
        return false;
    }
}
