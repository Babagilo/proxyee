package com.github.babagilo.proxy;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.handler.HttpProxyServerHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.server.HttpProxyCACertFactory;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class BabagiloProxy {

  //http代理隧道握手成功
  public final static HttpResponseStatus SUCCESS = new HttpResponseStatus(200,
      "Connection established");

  private HttpProxyCACertFactory caCertFactory;
  private BabagiloProxyConfig config;
  private HttpProxyInterceptInitializer proxyInterceptInitializer;
  private HttpProxyExceptionHandle httpProxyExceptionHandle;
  private ProxyConfig proxyConfig;

  private EventLoopGroup bossGroup;
  private EventLoopGroup workerGroup;

  private void init() {
    if (config == null) {
      config = new BabagiloProxyConfig();
    }
    config.setProxyLoopGroup(new NioEventLoopGroup(config.getNumberOfProxyGroupThreads()));

    if (config.isHandleSsl()) {
      try {
        config.setClientSslCtx(
            SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build());
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        X509Certificate caCert;
        PrivateKey caPriKey;
        if (caCertFactory == null) {
          caCert = CertUtil.loadCert(classLoader.getResourceAsStream("ca.crt"));
          caPriKey = CertUtil.loadPriKey(classLoader.getResourceAsStream("ca_private.der"));
        } else {
          caCert = caCertFactory.getCACert();
          caPriKey = caCertFactory.getCAPriKey();
        }
        //读取CA证书使用者信息
        config.setIssuer(CertUtil.getSubject(caCert));
        //读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
        config.setCaNotBefore(caCert.getNotBefore());
        config.setCaNotAfter(caCert.getNotAfter());
        //CA私钥用于给动态生成的网站SSL证书签证
        config.setCaPriKey(caPriKey);
        //生产一对随机公私钥用于网站SSL证书动态创建
        KeyPair keyPair = CertUtil.genKeyPair();
        config.setServerPriKey(keyPair.getPrivate());
        config.setServerPubKey(keyPair.getPublic());
      } catch (Exception e) {
        config.setHandleSsl(false);
      }
    }
    if (proxyInterceptInitializer == null) {
      proxyInterceptInitializer = new HttpProxyInterceptInitializer();
    }
    if (httpProxyExceptionHandle == null) {
      httpProxyExceptionHandle = new HttpProxyExceptionHandle();
    }
  }

  /**
   * Configure the Server
   * 
   * @param serverConfig
   * @return
   */
  public BabagiloProxy (BabagiloProxyConfig serverConfig) {
    this.config = serverConfig;
  }

  public BabagiloProxy proxyInterceptInitializer(
      HttpProxyInterceptInitializer proxyInterceptInitializer) {
    this.proxyInterceptInitializer = proxyInterceptInitializer;
    return this;
  }

  public BabagiloProxy httpProxyExceptionHandle(
      HttpProxyExceptionHandle httpProxyExceptionHandle) {
    this.httpProxyExceptionHandle = httpProxyExceptionHandle;
    return this;
  }

  public BabagiloProxy proxyConfig(ProxyConfig proxyConfig) {
    this.proxyConfig = proxyConfig;
    return this;
  }

  public BabagiloProxy caCertFactory(HttpProxyCACertFactory caCertFactory) {
    this.caCertFactory = caCertFactory;
    return this;
  }

  public void run() throws InterruptedException {
    init();
    bossGroup = new NioEventLoopGroup(1);
    workerGroup = new NioEventLoopGroup(config.getNumberOfWorkerGroupThreads());
    try {
      ServerBootstrap b = new ServerBootstrap();
      b.group(bossGroup, workerGroup)
          .channel(NioServerSocketChannel.class)
          .option(ChannelOption.SO_BACKLOG, 100)
//          .handler(new LoggingHandler(LogLevel.DEBUG))
          .childHandler(new ChannelInitializer<SocketChannel>() {

            @Override
            protected void initChannel(SocketChannel ch) throws Exception {
              ch.pipeline().addLast("httpCodec", new HttpServerCodec());
              ch.pipeline().addLast("serverHandle",
                  new HttpProxyServerHandle(config, proxyInterceptInitializer, proxyConfig,
                      httpProxyExceptionHandle));
            }
          });
      //Start the server
      ChannelFuture f = b.bind(config.getHost(), config.getPort()).sync();
      //Wait until the server socket is closed
      System.out.format("BabagiloProxy is listening at http://%s:%d%n",
              config.getHost(), config.getPort());
      f.channel().closeFuture().sync();
    } finally {
      bossGroup.shutdownGracefully();
      workerGroup.shutdownGracefully();
    }
  }

  public void close() {
    config.getProxyLoopGroup().shutdownGracefully();
    bossGroup.shutdownGracefully();
    workerGroup.shutdownGracefully();
    CertPool.clear();
  }

}
