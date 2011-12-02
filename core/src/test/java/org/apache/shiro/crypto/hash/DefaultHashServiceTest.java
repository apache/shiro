package org.apache.shiro.crypto.hash;

import junit.framework.TestCase;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.junit.Test;

import java.util.Arrays;

/**
 * Test for {@link DefaultHashService} class.
 *
 */
public class DefaultHashServiceTest {

	/**
	 * If the same string is hashed twice and no salt was supplied, hashed
	 * result should be different in each case.
	 */
	@Test
	public void testOnlyRandomSaltRandomness() {
		HashService hashService = createHashService();

		Hash firstHash = hashString(hashService, "password");
		Hash secondHash = hashString(hashService, "password");

		assertNotEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	/**
	 * If a string is hashed and no salt was supplied, random salt is generated.
	 * Hash of the same string with generated random salt should return the
	 * same result.
	 */
	@Test
	public void testOnlyRandomSaltReturn() {
		HashService hashService = createHashService();

		Hash firstHash = hashString(hashService, "password");
		Hash secondHash = hashString(hashService, "password", firstHash.getSalt().getBytes());

		TestCase.assertEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	/**
	 * Two different strings hashed with the same salt should result in two different
	 * hashes.
	 */
	@Test
	public void testOnlyRandomSaltHash() {
		HashService hashService = createHashService();

		Hash firstHash = hashString(hashService, "password");
		Hash secondHash = hashString(hashService, "password2", firstHash.getSalt().getBytes());

		assertNotEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	/**
	 * If the same string is hashed twice and only base salt was supplied, hashed
	 * result should be different in each case.
	 */
	@Test
	public void testBothSaltsRandomness() {
		HashService hashService = createHashServiceWithSalt();

		Hash firstHash = hashString(hashService, "password");
		Hash secondHash = hashString(hashService, "password");

		assertNotEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	/**
	 * If a string is hashed and only base salt was supplied, random salt is generated.
	 * Hash of the same string with generated random salt should return the
	 * same result.
	 */
	@Test
	public void testBothSaltsReturn() {
		HashService hashService = createHashServiceWithSalt();

		Hash firstHash = hashString(hashService, "password");
		Hash secondHash = hashString(hashService, "password", firstHash.getSalt().getBytes());

		TestCase.assertEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	/**
	 * Two different strings hashed with the same salt should result in two different
	 * hashes.
	 */
	@Test
	public void testBothSaltsHash() {
		HashService hashService = createHashServiceWithSalt();

		Hash firstHash = hashString(hashService, "password");
		Hash secondHash = hashString(hashService, "password2", firstHash.getSalt().getBytes());

		assertNotEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	/**
	 * Hash result is different if the base salt is added.
	 */
	@Test
	public void testBaseSaltChangesResult() {
		HashService saltedhashService = createHashServiceWithSalt();
		HashService hashService = createHashService();

		Hash firstHash = hashStringPredictable(saltedhashService, "password");
		Hash secondHash = hashStringPredictable(hashService, "password");

		assertNotEquals(firstHash.toBase64(), secondHash.toBase64());
	}

	protected Hash hashString(HashService hashService, String string) {
        return hashService.computeHash(new HashRequest.Builder().setSource(string).build());
	}

	protected Hash hashString(HashService hashService, String string, byte[] salt) {
		return hashService.computeHash(new HashRequest.Builder().setSource(string).setSalt(salt).build());
	}

	private Hash hashStringPredictable(HashService hashService, String string) {
		byte[] salt = new byte[20];
		Arrays.fill(salt, (byte) 2);
		return hashService.computeHash(new HashRequest.Builder().setSource(string).setSalt(salt).build());
	}

	private HashService createHashService() {
		return new DefaultHashService();
	}

	private HashService createHashServiceWithSalt() {
		DefaultHashService defaultHashService = new DefaultHashService();
		defaultHashService.setPrivateSalt(new SecureRandomNumberGenerator().nextBytes());
		
		return defaultHashService;
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
