package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.proxy.ProxyHandler;
import com.github.babagilo.proxy.BabagiloProxyHandler;

/**
 * http代理隧道，转发原始报文
 */
public class TunnelProxyInitializer extends ChannelInitializer<Channel> {

	private Channel client_proxy_channel;
	private ProxyHandler proxyHandler;

	public TunnelProxyInitializer(Channel client_proxy_channel, ProxyHandler proxyHandler) {
		this.client_proxy_channel = client_proxy_channel;
		this.proxyHandler = proxyHandler;
	}

	@Override
	protected void initChannel(Channel ch) throws Exception {
		if (proxyHandler != null) {
			ch.pipeline().addLast(proxyHandler);
		}
		ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
			@Override
			public void channelRead(ChannelHandlerContext ctx0, Object msg0) throws Exception {
				client_proxy_channel.writeAndFlush(msg0);
			}

			@Override
			public void channelUnregistered(ChannelHandlerContext ctx0) throws Exception {
				ctx0.channel().close();
				client_proxy_channel.close();
			}

			@Override
			public void exceptionCaught(ChannelHandlerContext ctx0, Throwable cause) throws Exception {
				ctx0.channel().close();
				client_proxy_channel.close();
				HttpProxyExceptionHandle exceptionHandle = ((BabagiloProxyHandler) client_proxy_channel.pipeline()
						.get("serverHandle")).getExceptionHandle();
				exceptionHandle.afterCatch(client_proxy_channel, ctx0.channel(), cause);
			}
		});
	}
}
