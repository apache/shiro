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
package org.apache.shiro.testing.jakarta.ee;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Test fixture that creates a container-managed session so the client can inspect its session cookie.
 */
@WebServlet(CreateSessionServlet.PATH)
public class CreateSessionServlet extends HttpServlet {
    static final String PATH = "/create-container-session";
    private static final long serialVersionUID = 1L;

    /**
     * Creates a session if needed and returns HTTP 204.
     *
     * @param request the request whose session is created or reused
     * @param response the response that carries the session cookie when a new session is created
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        request.getSession(true);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
