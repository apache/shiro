package org.jsecurity.support;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.*;

/**
 *
 */
public class DefaultPrincipalsConverter implements PrincipalsConverter {

    private static final String CHAR_ENCODING = "UTF8";

    public String toString(Object principals) {
        if (principals == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(bos));
        encoder.writeObject(principals);
        encoder.close();

        try {
            return bos.toString(CHAR_ENCODING);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Unable to convert byte array to UTF-8.  " +
                    "This is required to be supported on all 1.3+ JVMs.  Unable to continue");
        }
    }

    public Object fromString(String src) {
        if (src == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        ByteArrayInputStream bis = null;
        try {
            bis = new ByteArrayInputStream(src.getBytes(CHAR_ENCODING));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Unable to convert byte array to UTF-8.  " +
                    "This is required to be supported on all 1.3+ JVMs.  Unable to continue");
        }


        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(bis));
        Object o = decoder.readObject();
        decoder.close();
        return o;
    }
}
