package keys;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.EllipticCurveProvider;
import io.jsonwebtoken.impl.crypto.RsaProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.perf4j.LoggingStopWatch;
import org.perf4j.StopWatch;

public class PrivateKeyPoc {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		StopWatch perf = new LoggingStopWatch();
		System.out.println("Test RSA");
		testRSA();
		System.out.println("End test");
		perf.lap("RSA");	
		
		System.out.println("Test Elliptic");
		testElliptic();
		System.out.println("End test");
		perf.stop("Elliptic");
	}

	private static void testRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		KeyPair pair = RsaProvider.generateKeyPair();
		testKeyPair(pair, SignatureAlgorithm.RS256);
	}
	
	private static void testElliptic() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyPair pair = EllipticCurveProvider.generateKeyPair(SignatureAlgorithm.ES256);
		testKeyPair(pair, SignatureAlgorithm.ES256);
	}

	private static void testKeyPair(KeyPair pair, SignatureAlgorithm algo) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();
		
		String factoryName;
		switch (algo) {
		case RS256:
			factoryName = "RSA";
			break;
		case ES256:
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
			ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(privateKey.getEncoded()), spec);
			KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
			System.out.println(Jwts.builder().setSubject("Joe").signWith(algo, kf.generatePrivate(prvkey)).compact());
			factoryName = "ECDSA";
			break;
		default:
			throw new RuntimeException("unknown factory name");
		}
		KeyFactory factory = KeyFactory.getInstance(factoryName);
		PrivateKey privateKey2 = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()));
		PublicKey publicKey2 = factory.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
		
		System.out.println(Jwts.builder().setSubject("Joe").signWith(algo, privateKey).compact());
		System.out.println(Jwts.builder().setSubject("Joe").signWith(algo, privateKey2).compact());
		String s = Jwts.builder().setSubject("Joe").signWith(algo, privateKey2).compact();
		System.out.println(s);
		System.out.println(s.length());
		
		Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey2).parseClaimsJws(s);
		System.out.println(claims.getBody().getSubject());
	}
}
