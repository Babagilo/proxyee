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
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class BabagiloProxy {
	private ProxyMode proxyMode;

	private HttpProxyInterceptInitializer proxyInterceptInitializer;
	private HttpProxyExceptionHandle httpProxyExceptionHandle;
	private ProxyConfig proxyConfig;

	private EventLoopGroup bossGroup;
	private EventLoopGroup workerGroup;
	private EventLoopGroup forwardGroup;
	
	private PrivateKey serverPrivateKey;
	private PrivateKey ca_private_key;
	private PublicKey serverPubKey;
	private String issuer;
	private Date caNotBefore;
	private Date caNotAfter;

	public BabagiloProxy() throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
		this(ProxyMode.TUNNEL);
	}

	/**
	 * 
	 * @param proxyMode - support TUNNEL or INTERCEPT
	 * @throws IOException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws CertificateException 
	 */
	public BabagiloProxy(ProxyMode proxyMode) throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
		setProxyMode(proxyMode);
	}
	
	private void setProxyMode(ProxyMode proxyMode) throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
		this.proxyMode = proxyMode;
		if (proxyMode == ProxyMode.INTERCEPT) {
			
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
	}

	
	public BabagiloProxy configureBasicAuthentication(File authFile) throws IOException {
		Authenticator fa = new FileAuthenticator(authFile);
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
		forwardGroup = new NioEventLoopGroup();
		try {
			ServerBootstrap b = new ServerBootstrap();
			b.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class).option(ChannelOption.SO_BACKLOG, 100)
					//.handler(new LoggingHandler(LogLevel.INFO))
					.childHandler(new ChannelInitializer<SocketChannel>() {

						@Override
						protected void initChannel(SocketChannel ch) throws Exception {
							BabagiloProxyHandler serverHandler = proxyMode == ProxyMode.TUNNEL
									? new BabagiloProxyHandler(forwardGroup)
									: new BabagiloProxyHandler(forwardGroup, proxyInterceptInitializer,
											proxyConfig, httpProxyExceptionHandle,  serverPrivateKey,  issuer,  ca_private_key,
											 caNotBefore,  caNotAfter,  serverPubKey);

							ch.pipeline().addLast("httpCodec", new HttpServerCodec());
							ch.pipeline().addLast("serverHandle", serverHandler);
						}
					});
			// Start the server
			ChannelFuture f = b.bind(port).sync();
			// Wait until the server socket is closed
			//System.err.format("BabagiloProxy is listening at localhost:%d; Mode: %s%n", port, this.proxyMode);
			f.channel().closeFuture().sync();
			
		} finally {
			bossGroup.shutdownGracefully();
			workerGroup.shutdownGracefully();
			forwardGroup.shutdownGracefully();
		}
	}

	public void close() {
		forwardGroup.shutdownGracefully();
		bossGroup.shutdownGracefully();
		workerGroup.shutdownGracefully();
		CertPool.clear();
	}

}
