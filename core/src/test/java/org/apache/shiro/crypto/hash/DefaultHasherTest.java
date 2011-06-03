package org.apache.shiro.crypto.hash;

import java.util.Arrays;

import junit.framework.TestCase;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.util.ByteSource;
import org.junit.Test;

/**
 * Test for {@link DefaultHasher} class.
 *
 */
public class DefaultHasherTest {

	/**
	 * If the same string is hashed twice and no salt was supplied, hashed
	 * result should be different in each case.
	 */
	@Test
	public void testOnlyRandomSaltRandomness() {
		Hasher hasher = createHasher();

		HashResponse firstHash = hashString(hasher, "password");
		HashResponse secondHash = hashString(hasher, "password");

		assertNotEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	/**
	 * If a string is hashed and no salt was supplied, random salt is generated.
	 * Hash of the same string with generated random salt should return the
	 * same result.
	 */
	@Test
	public void testOnlyRandomSaltReturn() {
		Hasher hasher = createHasher();

		HashResponse firstHash = hashString(hasher, "password");
		HashResponse secondHash = hashString(hasher, "password", firstHash.getSalt().getBytes());

		TestCase.assertEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	/**
	 * Two different strings hashed with the same salt should result in two different
	 * hashes.
	 */
	@Test
	public void testOnlyRandomSaltHash() {
		Hasher hasher = createHasher();

		HashResponse firstHash = hashString(hasher, "password");
		HashResponse secondHash = hashString(hasher, "password2", firstHash.getSalt().getBytes());

		assertNotEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	/**
	 * If the same string is hashed twice and only base salt was supplied, hashed
	 * result should be different in each case.
	 */
	@Test
	public void testBothSaltsRandomness() {
		Hasher hasher = createHasherWithSalt();

		HashResponse firstHash = hashString(hasher, "password");
		HashResponse secondHash = hashString(hasher, "password");

		assertNotEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	/**
	 * If a string is hashed and only base salt was supplied, random salt is generated.
	 * Hash of the same string with generated random salt should return the
	 * same result.
	 */
	@Test
	public void testBothSaltsReturn() {
		Hasher hasher = createHasherWithSalt();

		HashResponse firstHash = hashString(hasher, "password");
		HashResponse secondHash = hashString(hasher, "password", firstHash.getSalt().getBytes());

		TestCase.assertEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	/**
	 * Two different strings hashed with the same salt should result in two different
	 * hashes.
	 */
	@Test
	public void testBothSaltsHash() {
		Hasher hasher = createHasherWithSalt();

		HashResponse firstHash = hashString(hasher, "password");
		HashResponse secondHash = hashString(hasher, "password2", firstHash.getSalt().getBytes());

		assertNotEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	/**
	 * Hash result is different if the base salt is added.
	 */
	@Test
	public void testBaseSaltChangesResult() {
		Hasher saltedHasher = createHasherWithSalt();
		Hasher hasher = createHasher();

		HashResponse firstHash = hashStringPredictable(saltedHasher, "password");
		HashResponse secondHash = hashStringPredictable(hasher, "password");

		assertNotEquals(firstHash.getHash().toBase64(), secondHash.getHash().toBase64());
	}

	protected HashResponse hashString(Hasher hasher, String string) {
		return hasher.computeHash(new SimpleHashRequest(ByteSource.Util.bytes(string)));
	}

	protected HashResponse hashString(Hasher hasher, String string, byte[] salt) {
		return hasher.computeHash(new SimpleHashRequest(ByteSource.Util.bytes(string), ByteSource.Util.bytes(salt)));
	}

	private HashResponse hashStringPredictable(Hasher hasher, String string) {
		byte[] salt = new byte[20];
		Arrays.fill(salt, (byte) 2);
		return hasher.computeHash(new SimpleHashRequest(ByteSource.Util.bytes(string), ByteSource.Util.bytes(salt)));
	}

	private Hasher createHasher() {
		return new DefaultHasher();
	}

	private Hasher createHasherWithSalt() {
		DefaultHasher defaultHasher = new DefaultHasher();
		defaultHasher.setBaseSalt((new SecureRandomNumberGenerator()).nextBytes().getBytes());
		
		return defaultHasher;
	}

	private void assertNotEquals(String str1, String str2) {
		boolean equals = equals(str1, str2);
		if (equals)
			TestCase.fail("Strings are supposed to be different.");
	}

	protected boolean equals(String str1, String str2) {
		if (str1 == null)
			return str2 == null;

		return str1.equals(str2);
	}
}
