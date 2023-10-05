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
package org.apache.shiro.testing.jakarta.ee.servlets;

import org.apache.shiro.testing.logcapture.LogCapture;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.logging.LogRecord;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

/**
 * Log Capture servlet
 */
@WebServlet("/lastException")
public class ExceptionServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PrintWriter out = resp.getWriter();
        resp.setContentType(TEXT_PLAIN);
        resp.setCharacterEncoding(StandardCharsets.UTF_8.name());

        LogRecord record = LogCapture.get().poll();
        while (record != null) {
            if (record.getThrown() != null) {
                out.printf("%s: %s", record.getLevel(), record.getThrown());
                out.print(System.lineSeparator());
            }
            record = LogCapture.get().poll();
        }
        out.flush();
    }
}
