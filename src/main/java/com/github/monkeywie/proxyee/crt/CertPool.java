package com.github.monkeywie.proxyee.crt;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

public class CertPool {

	private static Map<Integer, Map<String, X509Certificate>> certCache = new WeakHashMap<>();

	public static X509Certificate getCert(Integer port, String host, String issuer, PrivateKey caPriKey,
			Date caNotBefore, Date caNotAfter, PublicKey serverPubKey)
			throws CertIOException, OperatorCreationException, CertificateException {
		X509Certificate cert = null;
		if (host != null) {
			Map<String, X509Certificate> portCertCache = certCache.get(port);
			if (portCertCache == null) {
				portCertCache = new HashMap<>();
				certCache.put(port, portCertCache);
			}
			String key = host.trim().toLowerCase();
			if (portCertCache.containsKey(key)) {
				return portCertCache.get(key);
			} else {
				cert = CertUtil.genCert(issuer, caPriKey, caNotBefore, caNotAfter, serverPubKey, key);
				portCertCache.put(key, cert);
			}
		}
		return cert;
	}

	public static void clear() {
		certCache.clear();
	}
}
