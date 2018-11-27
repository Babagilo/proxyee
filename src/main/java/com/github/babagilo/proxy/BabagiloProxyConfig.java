package com.github.babagilo.proxy;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import com.github.monkeywie.proxyee.crt.CertUtil;


import io.netty.channel.EventLoopGroup;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class BabagiloProxyConfig {
	private SslContext clientSslCtx;
	private String issuer;
	private Date caNotBefore;
	private Date caNotAfter;
	
	// CA私钥用于给动态生成的网站SSL证书签证
	private PrivateKey ca_private_key;
	private PrivateKey serverPriKey;
	private PublicKey serverPubKey;
	private EventLoopGroup proxyLoopGroup;

	private int nWorkerGroupThreads;
	private int nProxyGroupThreads;
	private boolean manInTheMiddleMode;
	private int port;
	private String host;

	/**
	 * @param port               - listening port
	 * @param manInTheMiddleMode - true, Proxy will offload the HTTPS requests and
	 *                           play man-in-the-middle sniffing
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * 
	 */
	public BabagiloProxyConfig(String host, int port, boolean manInTheMiddleMode) throws NoSuchAlgorithmException,
			NoSuchProviderException, CertificateException, InvalidKeySpecException, IOException {
		setNumberOfWorkerGroupThreads(1);
		setNumberOfProxyGroupThreads(1);
		this.host = host;
		this.port = port;
		setManInTheMiddleMode(manInTheMiddleMode);
	}

	public void setManInTheMiddleMode(boolean manInTheMiddleMode) throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
		this.manInTheMiddleMode = manInTheMiddleMode;
		if (manInTheMiddleMode) {
			this.clientSslCtx = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
					.build();
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			X509Certificate caCert = CertUtil.loadCert(classLoader.getResourceAsStream("ca.crt"));
			ca_private_key = CertUtil.loadPriKey(classLoader.getResourceAsStream("ca_private.der"));

			// 读取CA证书使用者信息
			setIssuer(CertUtil.getSubject(caCert));
			// 读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
			setCaNotBefore(caCert.getNotBefore());
			setCaNotAfter(caCert.getNotAfter());

			// 生产一对随机公私钥用于网站SSL证书动态创建
			KeyPair keyPair = CertUtil.genKeyPair();
			setServerPriKey(keyPair.getPrivate());
			setServerPubKey(keyPair.getPublic());
		}
	}

	/**
	 *
	 * Default Constructor, server will be listening on port 127.0.0.1:<port> and
	 * will not offload TLS traffic.
	 *
	 * @param port
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */
	public BabagiloProxyConfig(int port) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException,
			InvalidKeySpecException, IOException {
		this("127.0.0.1", port, false);
	}

	public SslContext getClientSslCtx() {
		return clientSslCtx;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public Date getCaNotBefore() {
		return caNotBefore;
	}

	public void setCaNotBefore(Date caNotBefore) {
		this.caNotBefore = caNotBefore;
	}

	public Date getCaNotAfter() {
		return caNotAfter;
	}

	public void setCaNotAfter(Date caNotAfter) {
		this.caNotAfter = caNotAfter;
	}

	public PrivateKey getCaPriKey() {
		return ca_private_key;
	}

	public PrivateKey getServerPrivateKey() {
		return serverPriKey;
	}

	public void setServerPriKey(PrivateKey serverPriKey) {
		this.serverPriKey = serverPriKey;
	}

	public PublicKey getServerPubKey() {
		return serverPubKey;
	}

	public void setServerPubKey(PublicKey serverPubKey) {
		this.serverPubKey = serverPubKey;
	}

	public EventLoopGroup getProxyLoopGroup() {
		return proxyLoopGroup;
	}

	public void setProxyLoopGroup(EventLoopGroup proxyLoopGroup) {
		this.proxyLoopGroup = proxyLoopGroup;
	}

	public boolean isManInTheMiddleMode() {
		return manInTheMiddleMode;
	}

	public int getNumberOfWorkerGroupThreads() {
		return nWorkerGroupThreads;
	}

	public void setNumberOfWorkerGroupThreads(int workerGroupThreads) {
		this.nWorkerGroupThreads = workerGroupThreads;
	}

	public int getNumberOfProxyGroupThreads() {
		return nProxyGroupThreads;
	}

	public void setNumberOfProxyGroupThreads(int proxyGroupThreads) {
		this.nProxyGroupThreads = proxyGroupThreads;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}
}
