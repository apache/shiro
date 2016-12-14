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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Spring MVC controller responsible for rendering the Shiro Spring sample
 * application index page.
 *
 * @since 0.1
 */
@Controller
@RequestMapping("/s/index")
public class IndexController {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    @Autowired
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

    @RequestMapping(method = RequestMethod.GET)
    protected String doGet(Model model) {

        buildModel(model);
        model.addAttribute("value", sampleManager.getValue());

        return "sampleIndex";
    }

    protected Model buildModel(Model model) {

        Subject subject = SecurityUtils.getSubject();
        boolean hasRole1 = subject.hasRole("role1");
        boolean hasRole2 = subject.hasRole("role2");

        model.addAttribute("hasRole1", hasRole1);
        model.addAttribute("hasRole2", hasRole2);

        Session session = subject.getSession();
        Map<Object, Object> sessionAttributes = new LinkedHashMap<Object, Object>();
        for (Object key : session.getAttributeKeys()) {
            sessionAttributes.put(key, session.getAttribute(key));
        }
        model.addAttribute("sessionAttributes", sessionAttributes);

        model.addAttribute("subjectSession", subject.getSession());
        return model;
    }

    @RequestMapping(method = RequestMethod.POST)
    protected String doPost(@RequestParam("value") String newSessionValue, Model model) {

        sampleManager.setValue(newSessionValue);

        buildModel(model);
        model.addAttribute("value", sampleManager.getValue());

        return "sampleIndex";
    }

}
