package com.github.babagilo.proxy;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.net.ssl.SSLException;

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


  private BabagiloProxyConfig config;
  private HttpProxyInterceptInitializer proxyInterceptInitializer;
  private HttpProxyExceptionHandle httpProxyExceptionHandle;
  private ProxyConfig proxyConfig;

  private EventLoopGroup bossGroup;
  private EventLoopGroup workerGroup;

  private void init() throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
    config.setProxyLoopGroup(new NioEventLoopGroup(config.getNumberOfProxyGroupThreads()));



    if (httpProxyExceptionHandle == null) {
      httpProxyExceptionHandle = new HttpProxyExceptionHandle();
    }
  }

  /**
   * Configure the Server
   * 
   * @param config
   * @return
   */
  public BabagiloProxy (BabagiloProxyConfig config) {
    this.config = config;
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

  public void run() throws InterruptedException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
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
      System.out.format("BabagiloProxy is listening at %s:%d%n", config.getHost(), config.getPort());
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
