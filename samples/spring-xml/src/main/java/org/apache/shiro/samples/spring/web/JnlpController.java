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
package org.apache.shiro.samples.spring.web;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

/**
 * Controller used to dynamically build a JNLP file used to launch the Shiro
 * Spring WebStart sample application.
 *
 * @since 0.1
 */
public class JnlpController extends AbstractController {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private String jnlpView;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setJnlpView(String jnlpView) {
        this.jnlpView = jnlpView;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {

        Subject subject = SecurityUtils.getSubject();
        Session session = null;

        if (subject != null) {
            session = subject.getSession();
        }
        if (session == null) {
            String msg = "Expected a non-null Shiro session.";
            throw new IllegalArgumentException(msg);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("http://");
        sb.append(request.getServerName());
        if (request.getServerPort() != 80) {
            sb.append(":");
            sb.append(request.getServerPort());
        }
        sb.append(request.getContextPath());

        // prevent JNLP caching by setting response headers
        response.setHeader("cache-control", "no-cache");
        response.setHeader("pragma", "no-cache");

        Map<String, Object> model = new HashMap<String, Object>();
        model.put("codebaseUrl", sb.toString());
        model.put("sessionId", session.getId());
        return new ModelAndView(jnlpView, model);
    }
}
