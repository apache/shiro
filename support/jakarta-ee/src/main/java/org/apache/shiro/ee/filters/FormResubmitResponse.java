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
package org.apache.shiro.ee.filters;

import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.LOCATION;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.Closeable;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.experimental.Delegate;
import org.omnifaces.servlet.BufferedHttpServletResponse;

/**
 * Captures a replay's status, headers, cookies and body instead of committing them to the browser.
 * Nothing reaches the browser response until {@link #applyTo} is called for a successful replay,
 * so view-state GETs, failed attempts and Faces error handling (which resets the response)
 * cannot disturb what the login request has already written, such as session cookies.
 */
final class FormResubmitResponse extends BufferedHttpServletResponse {
    private final List<Consumer<HttpServletResponse>> deferred = new ArrayList<>();
    private final @Delegate(types = Captured.class) HttpServletResponse recorder;
    private @Getter @Setter int status = SC_OK;
    private ClosableOutputStream outputStream;

    /**
     * Header and cookie operations are recorded, to be replayed by {@link #applyTo}.
     * Redirects and errors are captured as status (and Location header) instead,
     * while content lengths are dropped since the body may be translated by the caller.
     */
    @SuppressWarnings("unused")
    private interface Captured {
        void setHeader(String name, String value);
        void addHeader(String name, String value);
        void setIntHeader(String name, int value);
        void addIntHeader(String name, int value);
        void setDateHeader(String name, long date);
        void addDateHeader(String name, long date);
        void addCookie(Cookie cookie);
        void sendRedirect(String location) throws IOException;
        void sendRedirect(String location, int sc) throws IOException;
        void sendRedirect(String location, boolean clearBuffer) throws IOException;
        void sendRedirect(String location, int sc, boolean clearBuffer) throws IOException;
        void sendError(int sc) throws IOException;
        void sendError(int sc, String message) throws IOException;
        void setContentLength(int len);
        void setContentLengthLong(long len);
    }

    FormResubmitResponse(HttpServletResponse response) {
        super(new UncommittedResponse(response));
        recorder = (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {HttpServletResponse.class}, this::defer);
    }

    /**
     * Replays the captured header and cookie operations onto the browser response.
     * Status and body are left to the caller, which may translate them for the original client.
     *
     * @param target the browser response
     */
    void applyTo(HttpServletResponse target) {
        deferred.forEach(op -> op.accept(target));
    }

    private Object defer(Object proxy, Method method, Object[] args) {
        switch (method.getName()) {
            case "sendRedirect" -> redirect(args);
            case "sendError" -> setStatus((int) args[0]);
            case "setContentLength", "setContentLengthLong" -> { }
            case "equals", "hashCode", "toString" ->
                    throw new IllegalStateException("Cannot compare FormResubmitResponse instances");
            default -> deferred.add(target -> invoke(method, target, args));
        }
        return null;
    }

    /**
     * @param args of the (location [, status] [, clearBuffer]) overloads
     */
    private void redirect(Object[] args) {
        if (!(args[args.length - 1] instanceof Boolean clearBuffer) || clearBuffer) {
            resetBuffer();
        }
        setStatus(args.length > 1 && args[1] instanceof Integer sc ? sc : SC_FOUND);
        setHeader(LOCATION, (String) args[0]);
    }

    @SneakyThrows
    private static void invoke(Method method, HttpServletResponse target, Object[] args) {
        MethodHandles.publicLookup().unreflect(method).bindTo(target).invokeWithArguments(args);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        ServletOutputStream delegate = super.getOutputStream();
        if (outputStream == null) {
            outputStream = new ClosableOutputStream(delegate);
        }
        return outputStream;
    }

    /**
     * Container responses ignore a flush once the stream is closed, as a download writer may well do,
     * whereas the buffering base class throws
     */
    @Override
    public void flushBuffer() throws IOException {
        if (outputStream == null || !outputStream.closed) {
            super.flushBuffer();
        }
    }

    @Override
    public void resetBuffer() {
        // the base class only resets its own buffer here, since the wrapped response ignores reset()
        super.reset();
    }

    @Override
    public void reset() {
        super.reset();
        status = SC_OK;
        deferred.clear();
    }

    /**
     * Tracks whether the replayed component has closed the response stream
     */
    @RequiredArgsConstructor
    private static final class ClosableOutputStream extends ServletOutputStream {
        private final @Delegate(excludes = Closeable.class) ServletOutputStream delegate;
        private boolean closed;

        @Override
        public void close() throws IOException {
            closed = true;
            delegate.close();
        }
    }

    /**
     * Shields the browser response from a replay's commit-type operations,
     * that would otherwise reset or flush what the login request has already written.
     */
    private static final class UncommittedResponse extends HttpServletResponseWrapper {
        UncommittedResponse(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void reset() {
        }

        @Override
        public void flushBuffer() {
        }
    }
}
