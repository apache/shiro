package org.jsecurity;

import junit.framework.TestCase;
import org.jsecurity.util.ClassUtils;
import org.junit.Test;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 29, 2008
 * Time: 1:19:55 PM
 * To change this template use File | Settings | File Templates.
 */
public abstract class ExceptionTest extends TestCase {

    protected abstract Class getExceptionClass();

    @Test
    public void testNoArgConstructor() {
        ClassUtils.newInstance(getExceptionClass());
    }

    @Test
    public void testMsgConstructor() throws Exception {
        ClassUtils.newInstance(getExceptionClass(), "Msg");
    }

    @Test
    public void testCauseConstructor() throws Exception {
        ClassUtils.newInstance(getExceptionClass(), new Throwable() );
    }

    @Test
    public void testMsgCauseConstructor() {
        ClassUtils.newInstance(getExceptionClass(), "Msg", new Throwable() );
    }
}
