package com.github.babagilo.proxy;

import java.net.InetSocketAddress;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.babagilo.auth.Authenticator;
import com.github.babagilo.auth.Authorizer;
import com.github.monkeywie.proxyee.crt.CertPool;

import com.github.monkeywie.proxyee.handler.HttpProxyInitializer;
import com.github.monkeywie.proxyee.handler.TunnelProxyInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.proxy.ProxyHandleFactory;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoop;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.proxy.ProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.resolver.NoopAddressResolverGroup;
import io.netty.util.ReferenceCountUtil;

public class BabagiloProxyHandler extends ChannelInboundHandlerAdapter {
	Logger logger = Logger.getLogger(BabagiloProxyHandler.class.getName());
	// See Appendix B.  Protocol Data Structures and Constant Values
	// https://tools.ietf.org/html/rfc8446
	public static final byte SSL_HANDSHAKE = 22;

	private ChannelFuture forwardChannelFuture;
	private String origin_host;
	private int origin_port;
	private boolean isSsl = false;
	private int status = 0;

	private ProxyConfig proxyConfig;
	private HttpProxyInterceptInitializer interceptInitializer;
	private HttpProxyInterceptPipeline interceptPipeline;

	private List requestList;
	private boolean isConnect;

	private ProxyMode proxyMode;

	private EventLoop el;

	private PrivateKey serverPrivateKey;

	private String issuer;

	private PrivateKey caPriKey;

	private Date caNotBefore;

	private Date caNotAfter;

	private PublicKey serverPubKey;

	private Class<? extends SocketChannel> socketChannelClass;

	private Authenticator authenticator;

	private Authorizer authorizer;

	public HttpProxyInterceptPipeline getInterceptPipeline() {
		return interceptPipeline;
	}

	
	/**
	 * Constructor for TUNNEL_MODE
	 * 
	 * @param el
	 * @param socketChannelClass
	 */
	public BabagiloProxyHandler(EventLoop el, Class<? extends SocketChannel> socketChannelClass, Authenticator authenticator) {
		this.el = el;
		this.socketChannelClass = socketChannelClass;
		this.authenticator = authenticator;
		
		this.proxyMode = ProxyMode.TUNNEL;
	}
	/**
	 * Constructor for INTERCEPT_MODE
	 * 
	 * @param forwardGroup
	 * @param authorizer 
	 * @param serverConfig
	 * @param interceptInitializer
	 * @param proxyConfig
	 * @param exceptionHandle
	 */
	public BabagiloProxyHandler(EventLoop forwardGroup, Class<? extends SocketChannel> socketChannelClass,
			Authenticator authenticator,Authorizer authorizer, HttpProxyInterceptInitializer interceptInitializer, ProxyConfig proxyConfig,
			PrivateKey serverPrivateKey, String issuer, PrivateKey caPriKey,
			Date caNotBefore, Date caNotAfter, PublicKey serverPubKey) {
		this.el = forwardGroup;
		this.socketChannelClass = socketChannelClass;
		this.authenticator = authenticator;
		this.authorizer = authorizer;
		
		this.proxyMode = ProxyMode.INTERCEPT;

		this.proxyConfig = proxyConfig;
		this.interceptInitializer = interceptInitializer;

		this.serverPrivateKey = serverPrivateKey;
		this.issuer = issuer;
		this.caPriKey = caPriKey;
		this.caNotBefore = caNotBefore;
		this.caNotAfter = caNotAfter;
		this.serverPubKey = serverPubKey;
	}



	@Override
	public void channelRead(final ChannelHandlerContext ctx, final Object msg) throws Exception {

		if (msg instanceof HttpRequest) {
			HttpRequest httpRequest = (HttpRequest) msg;
			// 第一次建立连接取host和端口号和处理代理握手
			if (status == 0) {
				RequestProto requestProto = ProtoUtil.getRequestProto(httpRequest);
				if (requestProto == null) { // bad request
					ctx.channel().close();
					return;
				}
				status = 1;
				this.origin_host = requestProto.getHost();
				this.origin_port = requestProto.getPort();

				/*
				 * DefaultHttpRequest(decodeResult: success, version: HTTP/1.1) CONNECT
				 * clients6.google.com:443 HTTP/1.1 Host: clients6.google.com:443
				 * Proxy-Connection: keep-alive User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64;
				 * x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102
				 * Safari/537.36
				 * 
				 * DefaultHttpRequest(decodeResult: success, version: HTTP/1.1) CONNECT
				 * notifications.google.com:443 HTTP/1.1 Host: notifications.google.com:443
				 * Proxy-Connection: keep-alive User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64;
				 * x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102
				 * Safari/537.36 Proxy-Authorization: Basic bGl5b25nOmFiY2Q=
				 */
				if (HttpMethod.CONNECT.equals(httpRequest.method())) {// 建立代理握手
					status = 2;

					// extract proxy username and password
					String proxy_Authorization = httpRequest.headers().get("Proxy-Authorization");
					HttpResponse response;
					if (authenticator.authenticate(proxy_Authorization)) {
						response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
								new HttpResponseStatus(200, "Connection established"));
						ctx.writeAndFlush(response);
						ctx.channel().pipeline().remove("httpCodec");
					} else {
						// System.err.format("%s\nProxy-Authorization: %s\n",request.uri(),
						// proxy_Authorization);
						response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
								new HttpResponseStatus(407, "Authentication Required"));
						response.headers().add("Proxy-Authenticate", "Basic realm=\"Access to internal site\"");
						ctx.writeAndFlush(response);
					}
					return;
				}
			}
			interceptPipeline = buildPipeline();
			interceptPipeline.setRequestProto(new RequestProto(origin_host, origin_port, isSsl));
			// fix issues #27
			if (httpRequest.uri().indexOf("/") != 0) {
				URL url = new URL(httpRequest.uri());
				httpRequest.setUri(url.getFile());
			}
			interceptPipeline.beforeRequest(ctx.channel(), httpRequest);
		} else if (msg instanceof HttpContent) {
			if (status != 2) {
				interceptPipeline.beforeRequest(ctx.channel(), (HttpContent) msg);
			} else {
				ReferenceCountUtil.release(msg);
				status = 1;
			}
		} else { // ssl和websocket的握手处理
			// class io.netty.buffer.PooledUnsafeDirectByteBuf
			// System.out.println("122: " + msg.getClass());

			if (proxyMode == ProxyMode.INTERCEPT) {
				ByteBuf byteBuf = (ByteBuf) msg;
				if (byteBuf.getByte(0) == SSL_HANDSHAKE) {
					isSsl = true;
					int proxy_port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
					SslContext sslCtx = SslContextBuilder.forServer(serverPrivateKey, CertPool.getCert(proxy_port,
							this.origin_host, issuer, caPriKey, caNotBefore, caNotAfter, serverPubKey)).build();

					// System.out.println("164: " + ctx.pipeline());
//          164: DefaultChannelPipeline{(serverHandle = com.github.babagilo.proxy.BabagiloProxyHandler)}
//          
					ctx.pipeline().addFirst("httpCodec", new HttpServerCodec());
					ctx.pipeline().addFirst("sslHandle", sslCtx.newHandler(ctx.alloc()));
					// 重新过一遍pipeline，拿到解密后的的http报文
					ctx.pipeline().fireChannelRead(msg);
					return;
				}
			}
			handleProxyData(ctx.channel(), msg, false);
		}
	}

	@Override
	public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
		System.out.println(this + " channel is unregistered");
		if (forwardChannelFuture != null) {
			forwardChannelFuture.channel().close();
		}
		ctx.channel().close();
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
		if (forwardChannelFuture != null) {
			forwardChannelFuture.channel().close();
		}

		ctx.channel().close();

		logger.log(Level.FINE, "Execption happening on channel "+ctx.channel(),cause);
	}

	private void handleProxyData(Channel channel, Object msg, boolean isHttp) throws Exception {
		if (forwardChannelFuture == null) {
			if (isHttp && !(msg instanceof HttpRequest)) { // connection异常 还有HttpContent进来，不转发
				return;
			}
			ProxyHandler proxyHandler = ProxyHandleFactory.build(proxyConfig);
			/*
			 * 添加SSL client hello的Server Name Indication extension(SNI扩展) 有些服务器对于client
			 * hello不带SNI扩展时会直接返回Received fatal alert: handshake_failure(握手错误)
			 * 例如：https://cdn.mdn.mozilla.net/static/img/favicon32.7f3da72dcea1.png
			 */
			RequestProto requestProto = new RequestProto(origin_host, origin_port, isSsl);
			ChannelInitializer<Channel> channelInitializer = isHttp
					? new HttpProxyInitializer(channel, requestProto, proxyHandler)
					: new TunnelProxyInitializer(channel, proxyHandler);
			Bootstrap clientBootstrap = new Bootstrap();
			clientBootstrap.group(this.el).channel(this.socketChannelClass)
			.handler(channelInitializer);
			if (proxyConfig != null) {
				// 代理服务器解析DNS和连接
				clientBootstrap.resolver(NoopAddressResolverGroup.INSTANCE);
			}
			requestList = new LinkedList();
			forwardChannelFuture = clientBootstrap.connect(origin_host, origin_port);
			logger.fine(280 + " " + forwardChannelFuture + " is created on " + this);
			forwardChannelFuture.addListener((ChannelFutureListener) future -> {
				if (future.isSuccess()) {
					future.channel().writeAndFlush(msg);
					synchronized (requestList) {
						requestList.forEach(obj -> future.channel().writeAndFlush(obj));
						requestList.clear();
						isConnect = true;
					}
				} else {
					requestList.forEach(obj -> ReferenceCountUtil.release(obj));
					requestList.clear();
					future.channel().close();
					channel.close();
				}
			});
		} else {
			synchronized (requestList) {
				if (isConnect) {
					forwardChannelFuture.channel().writeAndFlush(msg);
				} else {
					requestList.add(msg);
				}
			}
		}
	}

	private HttpProxyInterceptPipeline buildPipeline() {
		HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept() {
			@Override
			public void beforeRequest(Channel clientChannel, HttpRequest httpRequest,
					HttpProxyInterceptPipeline pipeline) throws Exception {
				handleProxyData(clientChannel, httpRequest, true);
			}

			@Override
			public void beforeRequest(Channel clientChannel, HttpContent httpContent,
					HttpProxyInterceptPipeline pipeline) throws Exception {
				handleProxyData(clientChannel, httpContent, true);
			}

			@Override
			public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
					HttpProxyInterceptPipeline pipeline) throws Exception {
				clientChannel.writeAndFlush(httpResponse);
				if (HttpHeaderValues.WEBSOCKET.toString().equals(httpResponse.headers().get(HttpHeaderNames.UPGRADE))) {
					// websocket转发原始报文
					proxyChannel.pipeline().remove("httpCodec");
					clientChannel.pipeline().remove("httpCodec");
				}
			}

			@Override
			public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
					HttpProxyInterceptPipeline pipeline) throws Exception {
				clientChannel.writeAndFlush(httpContent);
			}
		});
		if (interceptInitializer != null) {
			interceptInitializer.init(interceptPipeline);
		}

		return interceptPipeline;
	}
}
