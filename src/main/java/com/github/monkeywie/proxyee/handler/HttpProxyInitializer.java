package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;

import javax.net.ssl.SSLException;

import com.github.babagilo.proxy.BabagiloProxyHandler;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.proxy.ProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

/**
 * HTTP代理，转发解码后的HTTP报文
 */
public class HttpProxyInitializer extends ChannelInitializer<Channel> {

	private Channel client_proxy_channel;
	private RequestProto requestProto;
	private ProxyHandler proxyHandler;
	private SslContext clientSSLContext;

	public HttpProxyInitializer(Channel client_proxy_channel, RequestProto requestProto, ProxyHandler proxyHandler) throws SSLException {
		this.client_proxy_channel = client_proxy_channel;
		this.requestProto = requestProto;
		this.proxyHandler = proxyHandler;
		this.clientSSLContext = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
		.build();
	}

	@Override
	protected void initChannel(Channel ch) throws Exception {
		if (proxyHandler != null) {
			ch.pipeline().addLast(proxyHandler);
		}
		if (requestProto.getSsl()) {
			ch.pipeline()
					.addLast(clientSSLContext
							.newHandler(ch.alloc(), requestProto.getHost(), requestProto.getPort()));
		}
		ch.pipeline().addLast("httpCodec", new HttpClientCodec());
		ch.pipeline().addLast("proxyClientHandle", new HttpProxyClientHandle(client_proxy_channel));
	}
}
