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
package org.apache.shiro.ee.filters;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.mgt.DefaultSecurityManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import static org.apache.shiro.SecurityUtils.getSecurityManager;
import static org.apache.shiro.ee.filters.FormResubmitSupport.FORM_DATA_CACHE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.decrypt;
import static org.apache.shiro.ee.filters.FormResubmitSupport.getRememberMeManager;
import static org.apache.shiro.web.filter.authc.NoAccessFilter.FORM_RESUBMIT_CHECK_SERVLET_PATH;

@Slf4j
@WebServlet(name = "ShiroFormResubmitValidator", urlPatterns = FORM_RESUBMIT_CHECK_SERVLET_PATH)
public class FormResubmitValidator extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        var rememberMeManager = getRememberMeManager();
        if (rememberMeManager == null || rememberMeManager.getCipherService() == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        } else {
            try {
                String formDataKey = decrypt(request.getReader().lines().collect(Collectors.joining()), rememberMeManager);
                var cache = getSecurityManager(DefaultSecurityManager.class)
                        .getCacheManager().getCache(FORM_DATA_CACHE);
                Optional.ofNullable(cache.get(UUID.fromString(formDataKey))).orElseThrow(IllegalCallerException::new);
                String encryptedFormDataKey = rememberMeManager.getCipherService()
                        .encrypt(formDataKey.getBytes(StandardCharsets.UTF_8),
                        rememberMeManager.getEncryptionCipherKey()).toBase64();
                response.getWriter().write(encryptedFormDataKey);
                response.setStatus(HttpServletResponse.SC_OK);
            } catch (IOException | IllegalCallerException e) {
                log.warn("Form resubmit verification: invalid input or failed to write encrypted session id to response", e);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }
}
