package com.github.babagilo.proxy;

import io.netty.channel.EventLoopGroup;
import io.netty.handler.ssl.SslContext;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public class BabagiloProxyConfig {
	private SslContext clientSslCtx;
	private String issuer;
	private Date caNotBefore;
	private Date caNotAfter;
	private PrivateKey caPriKey;
	private PrivateKey serverPriKey;
	private PublicKey serverPubKey;
	private EventLoopGroup proxyLoopGroup;

	private int nWorkerGroupThreads;
	private int nProxyGroupThreads;
	private boolean handleSsl;
	private int port;
	private String host;

	/**
	 * Default Constructor
	 */
	public BabagiloProxyConfig() {
		setNumberOfWorkerGroupThreads(1);
		setNumberOfProxyGroupThreads(1);
		host = "127.0.0.1";
		port = 8964;
	}

	public SslContext getClientSslCtx() {
		return clientSslCtx;
	}

	public void setClientSslCtx(SslContext clientSslCtx) {
		this.clientSslCtx = clientSslCtx;
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
		return caPriKey;
	}

	public void setCaPriKey(PrivateKey caPriKey) {
		this.caPriKey = caPriKey;
	}

	public PrivateKey getServerPriKey() {
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

	public boolean isHandleSsl() {
		return handleSsl;
	}

	public void setHandleSsl(boolean handleSsl) {
		this.handleSsl = handleSsl;
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

	public void setPort(int i) {
		port = i;
		
	}
}
