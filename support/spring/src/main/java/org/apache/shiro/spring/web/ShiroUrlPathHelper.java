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
package org.apache.shiro.spring.web;

import org.apache.shiro.web.util.WebUtils;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.http.HttpServletRequest;

/**
 * A Spring UrlPathHelper that uses Shiro's path resolution logic.
 * @since 1.7.0
 */
public class ShiroUrlPathHelper extends UrlPathHelper {

    @Override
    public String getPathWithinApplication(HttpServletRequest request) {
        return WebUtils.getPathWithinApplication(request);
    }

    @Override
    public String getPathWithinServletMapping(HttpServletRequest request) {
        return WebUtils.getPathWithinApplication(request);
    }
}
