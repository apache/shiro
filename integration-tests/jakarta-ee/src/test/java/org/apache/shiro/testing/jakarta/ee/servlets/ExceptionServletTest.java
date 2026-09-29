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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.shiro.testing.logcapture.LogCapture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

@Execution(ExecutionMode.SAME_THREAD)
class ExceptionServletTest {
    private static final int LOG_CAPACITY = 10;
    private static final String PAYARA_MESSAGE = "Cannot invoke \"java.util.ResourceBundle.getString(String)\" "
            + "because the return value of \"java.util.logging.Logger.getResourceBundle()\" is null";

    @BeforeEach
    void setupLogging() {
        LogCapture.get().setupLogging(LOG_CAPACITY);
    }

    @AfterEach
    void resetLogging() {
        LogCapture.get().resetLogging();
    }

    @Test
    void ignoresPayaraLoggingBug() throws Exception {
        log(new NullPointerException(PAYARA_MESSAGE));
        log(new NullPointerException(PAYARA_MESSAGE));

        assertThat(getResponse()).isEmpty();
        assertThat(getResponse()).isEmpty();
    }

    @Test
    void reportsOtherExceptionsAfterPayaraLoggingBug() throws Exception {
        log(new NullPointerException(PAYARA_MESSAGE));
        log(null);
        log(new NullPointerException("another bug"));
        log(new NullPointerException());
        log(new IllegalStateException(PAYARA_MESSAGE));

        String newline = System.lineSeparator();
        assertThat(getResponse()).isEqualTo("WARNING: java.lang.NullPointerException: another bug" + newline
                + "WARNING: java.lang.NullPointerException" + newline
                + "WARNING: java.lang.IllegalStateException: " + PAYARA_MESSAGE + newline);
        assertThat(getResponse()).isEmpty();
    }

    private void log(Throwable thrown) {
        LogRecord record = new LogRecord(Level.WARNING, "test exception");
        record.setThrown(thrown);
        Logger.getLogger("").log(record);
    }

    private String getResponse() throws Exception {
        StringWriter output = new StringWriter();
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);
        expect(response.getWriter()).andReturn(new PrintWriter(output));
        replay(response);

        new ExceptionServlet().doGet(null, response);
        return output.toString();
    }
}

