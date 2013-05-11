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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.samples.spring.SampleManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.SimpleFormController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Spring MVC controller responsible for rendering the Shiro Spring sample
 * application index page.
 *
 * @since 0.1
 */
public class IndexController extends SimpleFormController {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    private SampleManager sampleManager;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setSampleManager(SampleManager sampleManager) {
        this.sampleManager = sampleManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    protected Object formBackingObject(HttpServletRequest request) throws Exception {
        SessionValueCommand command = (SessionValueCommand) createCommand();

        command.setValue(sampleManager.getValue());
        return command;
    }

    protected Map<String, Object> referenceData(HttpServletRequest request, Object command, Errors errors) throws Exception {
        Subject subject = SecurityUtils.getSubject();
        boolean hasRole1 = subject.hasRole("role1");
        boolean hasRole2 = subject.hasRole("role2");

        Map<String, Object> refData = new HashMap<String, Object>();
        refData.put("hasRole1", hasRole1);
        refData.put("hasRole2", hasRole2);

        Session session = subject.getSession();
        Map<Object, Object> sessionAttributes = new LinkedHashMap<Object, Object>();
        for (Object key : session.getAttributeKeys()) {
            sessionAttributes.put(key, session.getAttribute(key));
        }
        refData.put("sessionAttributes", sessionAttributes);

        refData.put("subjectSession", subject.getSession());
        return refData;
    }

    protected ModelAndView onSubmit(HttpServletRequest request, HttpServletResponse response, Object obj, BindException errors) throws Exception {
        SessionValueCommand command = (SessionValueCommand) obj;

        sampleManager.setValue(command.getValue());

        return showForm(request, response, errors);
    }

}
