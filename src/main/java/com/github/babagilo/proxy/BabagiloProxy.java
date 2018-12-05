package com.github.babagilo.proxy;

import java.io.File;
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
import java.util.logging.LogManager;

import com.github.babagilo.auth.Authenticator;
import com.github.babagilo.auth.Authorizer;
import com.github.babagilo.auth.FileAuthenticator;
import com.github.babagilo.auth.FileAuthorizer;
import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

public class BabagiloProxy {
	private ProxyMode proxyMode = ProxyMode.TUNNEL;

	private HttpProxyInterceptInitializer proxyInterceptInitializer;
	private HttpProxyExceptionHandle httpProxyExceptionHandle;
	private ProxyConfig proxyConfig;

	private EventLoopGroup bossGroup;
	private EventLoopGroup workerGroup;

	private PrivateKey serverPrivateKey;
	private PrivateKey ca_private_key;
	private PublicKey serverPubKey;
	private String issuer;
	private Date caNotBefore;
	private Date caNotAfter;

	private Authenticator authenticator = Authenticator.getSurepassAuthenticator();

	private Authorizer authorizer = Authorizer.getSurepassAuthorizer();

	/**
	 * Usage: java BabagiloProxy <9999> <authentication.txt> <authorization.txt>
	 * <filter.txt>
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		int port = Integer.parseInt(args[0]);
		File authnFile = new File(args[1]);
		File authzFile = new File(args[2]);

		new BabagiloProxy().configureBasicAuthentication(authnFile).configureAuthorization(authzFile).run(port);
	}

	private void configureEnableIntercept() throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException,
			IOException, NoSuchProviderException {
		this.proxyMode = ProxyMode.INTERCEPT;
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		X509Certificate caCert = CertUtil.loadCert(classLoader.getResourceAsStream("ca.crt"));
		ca_private_key = CertUtil.loadPriKey(classLoader.getResourceAsStream("ca_private.der"));

		// 读取CA证书使用者信息
		this.issuer = CertUtil.getSubject(caCert);
		// 读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
		this.caNotBefore = caCert.getNotBefore();
		this.caNotAfter = caCert.getNotAfter();

		// 生产一对随机公私钥用于网站SSL证书动态创建
		KeyPair keyPair = CertUtil.genKeyPair();
		this.serverPrivateKey = keyPair.getPrivate();
		this.serverPubKey = keyPair.getPublic();

	}

	public BabagiloProxy configureBasicAuthentication(File authFile) throws IOException {
		if (authFile.exists()) {
			this.authenticator = new FileAuthenticator(authFile);
		} else {
			System.err.println(authFile.getAbsolutePath() + " does not exists, no authentication is enforced");
		}
		return this;
	}

	public BabagiloProxy configureAuthorization(File authzFile) throws IOException, CertificateException,
			InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		if (authzFile.exists()) {
			this.authorizer = new FileAuthorizer(authzFile);
			configureEnableIntercept();
		} else {
			System.err.println(authzFile.getAbsolutePath() + " does not exists, all access are allowed");
		}
		return this;
	}

	public BabagiloProxy proxyInterceptInitializer(HttpProxyInterceptInitializer proxyInterceptInitializer) {
		this.proxyInterceptInitializer = proxyInterceptInitializer;
		return this;
	}

	public BabagiloProxy httpProxyExceptionHandle(HttpProxyExceptionHandle httpProxyExceptionHandle) {
		this.httpProxyExceptionHandle = httpProxyExceptionHandle;
		return this;
	}

	public BabagiloProxy proxyConfig(ProxyConfig proxyConfig) {
		this.proxyConfig = proxyConfig;
		return this;
	}

	public void run(int port) throws InterruptedException, CertificateException, InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchProviderException, IOException {
		bossGroup = new NioEventLoopGroup(1);
		workerGroup = new NioEventLoopGroup();

		try {
			ServerBootstrap b = new ServerBootstrap();
			b.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class).option(ChannelOption.SO_BACKLOG, 100)
					.handler(new LoggingHandler())
					.childHandler(new ChannelInitializer<SocketChannel>() {

						@Override
						protected void initChannel(SocketChannel ch) throws Exception {
							BabagiloProxyHandler serverHandler = proxyMode == ProxyMode.TUNNEL
									? new BabagiloProxyHandler(ch.eventLoop(), ch.getClass(), authenticator)
									: new BabagiloProxyHandler(ch.eventLoop(), ch.getClass(), authenticator, authorizer,
											proxyInterceptInitializer, proxyConfig, httpProxyExceptionHandle,
											serverPrivateKey, issuer, ca_private_key, caNotBefore, caNotAfter,
											serverPubKey);

							ch.pipeline().addLast("httpCodec", new HttpServerCodec());
							ch.pipeline().addLast("serverHandle", serverHandler);
						}
					});
			// Start the server
			ChannelFuture f = b.bind(port).sync();
			// Wait until the server socket is closed
			// System.err.format("BabagiloProxy is listening at localhost:%d; Mode: %s%n",
			// port, this.proxyMode);
			f.channel().closeFuture().sync();

		} finally {
			System.out.println("137 Gracefully shutdown");
			bossGroup.shutdownGracefully();
			workerGroup.shutdownGracefully();
		}
	}

	public void close() {
		System.out.println("Gracefully shutdown");
		bossGroup.shutdownGracefully();
		workerGroup.shutdownGracefully();
		CertPool.clear();
	}

}
