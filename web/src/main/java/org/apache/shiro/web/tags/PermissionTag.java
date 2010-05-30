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
package org.apache.shiro.web.tags;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

/**
 * @since 0.1
 */
public abstract class PermissionTag extends SecureTag {

    //TODO - complete JavaDoc

    private String name = null;

    public PermissionTag() {
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    protected void verifyAttributes() throws JspException {
        String permission = getName();

        if (permission == null || permission.length() == 0) {
            String msg = "The 'name' tag attribute must be set.";
            throw new JspException(msg);
        }
    }

    public int onDoStartTag() throws JspException {

        String p = getName();

        boolean show = showTagBody(p);
        if (show) {
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            return TagSupport.SKIP_BODY;
        }
    }

    protected boolean isPermitted(String p) {
        return getSubject() != null && getSubject().isPermitted(p);
    }

    protected abstract boolean showTagBody(String p);

}
