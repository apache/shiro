package org.apache.shiro.session.mgt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.junit.Test;

public class SimpleSessionTest {
    @Test
    public void serializeHost() throws IOException, ClassNotFoundException {
	SimpleSession session = new SimpleSession("localhost");
	assertEquals("localhost", serializeAndDeserialize(session).getHost());
    }
    
    @Test
    public void serializeExpired() throws IOException, ClassNotFoundException {
	SimpleSession session = new SimpleSession();
	session.setExpired(true);
	assertTrue(serializeAndDeserialize(session).isExpired());
    }
    
    private SimpleSession serializeAndDeserialize(SimpleSession session) throws IOException, ClassNotFoundException {
	ByteArrayOutputStream serialized = new ByteArrayOutputStream();
	ObjectOutputStream serializer = new ObjectOutputStream(serialized);
	serializer.writeObject(session);
	serializer.close();
	return (SimpleSession) new ObjectInputStream(new ByteArrayInputStream(serialized.toByteArray())).readObject(); 	
    }
}
