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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import javax.el.ELException;
import javax.faces.FacesException;
import javax.faces.component.UIComponent;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagConfig;
import javax.faces.view.facelets.TagHandler;
import java.io.IOException;

/**
 * Base class for all Shiro TagHandlers
 * 
 * @since 1.3
 */
public abstract class SecureTagHandler extends TagHandler {

    public SecureTagHandler(TagConfig config) {
        super(config);
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    public void apply(FaceletContext ctx, UIComponent parent) throws IOException, FacesException, ELException {
        if (showTagBody(ctx, parent)) {
            this.nextHandler.apply(ctx, parent);
        }
    }

    protected boolean showTagBody(FaceletContext ctx, UIComponent parent) {
        return showTagBody();
    }

    protected boolean showTagBody() {
        return false;
    }

}
