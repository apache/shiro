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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.component.UIOutput;
import javax.faces.context.FacesContext;
import java.io.IOException;

/**
 * Base class for JSF components.
 *
 * <p>OBS: Your subclass is responsible for saving the state of the component. See {@link org.apache.shiro.web.faces.tags.PrincipalTag}'s
 * StateHolder Methods for an exemple.
 * 
 * @since 1.3
 */
public abstract class SecureComponent extends UIOutput {

    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    @Override
    public void encodeAll(FacesContext ctx) throws IOException {
        verifyAttributes();
        doEncodeAll(ctx);
    }

    protected void verifyAttributes() throws IOException {
    }

    protected abstract void doEncodeAll(FacesContext ctx) throws IOException;
    
}
