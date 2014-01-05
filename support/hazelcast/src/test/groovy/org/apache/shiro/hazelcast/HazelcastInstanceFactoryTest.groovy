package org.apache.shiro.hazelcast

import com.hazelcast.core.HazelcastInstance
import com.hazelcast.core.LifecycleService
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class HazelcastInstanceFactoryTest {

    HazelcastInstanceFactory factory

    @Test
    void testInit() {

        def hc = createStrictMock(HazelcastInstance)

        factory = new HazelcastInstanceFactory() {
            @Override
            protected HazelcastInstance createInstance() {
                return hc;
            }
        }

        replay hc

        factory.init();

        def instance = factory.getInstance()

        assertSame instance, hc

        verify hc
    }

    @Test
    void testGetInstance() {

        def hc = createStrictMock(HazelcastInstance)
        int callCount = 0

        factory = new HazelcastInstanceFactory() {
            @Override
            protected HazelcastInstance createInstance() {
                callCount++
                return hc;
            }
        }

        replay hc

        def instance = factory.getInstance();

        assertSame instance, hc
        assertEquals 1, callCount

        //check that it does not create a new instance:
        instance = factory.getInstance()
        assertSame instance, hc
        assertEquals 1, callCount

        verify hc
    }

    @Test
    void testDestroy() {

        def hc = createStrictMock(HazelcastInstance)

        factory = new HazelcastInstanceFactory() {
            @Override
            protected HazelcastInstance createInstance() {
                return hc;
            }
        }

        def ls = createStrictMock(LifecycleService)

        expect(hc.getLifecycleService()).andStubReturn(ls)
        ls.shutdown()

        replay hc, ls

        def instance = factory.getInstance();

        assertSame instance, hc

        factory.destroy()

        verify hc, ls

    }

    @Test
    void testDestroyWithException() {

        def hc = createStrictMock(HazelcastInstance)

        factory = new HazelcastInstanceFactory() {
            @Override
            protected HazelcastInstance createInstance() {
                return hc;
            }
        }

        def ls = createStrictMock(LifecycleService)

        expect(hc.getLifecycleService()).andStubReturn(ls)
        ls.shutdown()
        expectLastCall().andThrow(new IllegalStateException("foo"))

        replay hc, ls

        def instance = factory.getInstance();

        assertSame instance, hc

        factory.destroy()

        verify hc, ls
    }

}
