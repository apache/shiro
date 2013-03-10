package org.apache.shiro.event

import org.junit.Test

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

/**
 * @since 1.3
 */
class EventTest {

    @Test
    void testDefault() {
        Object source = new Object()
        long start = System.currentTimeMillis()
        Event e = new DummyEvent(source)
        long stop = System.currentTimeMillis()

        assertSame source, e.source
        assertTrue start <= e.timestamp
        assertTrue stop >= e.timestamp
    }

    private class DummyEvent extends Event {
        DummyEvent(Object source) {
            super(source)
        }
    }
}
