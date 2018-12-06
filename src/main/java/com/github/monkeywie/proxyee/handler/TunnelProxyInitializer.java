package com.github.monkeywie.proxyee.handler;


import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.proxy.ProxyHandler;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.babagilo.proxy.BabagiloProxyHandler;

/**
 * http代理隧道，转发原始报文
 */
public class TunnelProxyInitializer extends ChannelInitializer<Channel> {
	Logger logger = Logger.getLogger(BabagiloProxyHandler.class.getName());
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
			public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
				ctx.channel().close();
				client_proxy_channel.close();
				logger.log(Level.FINE, "Execption happening on channel "+ctx.channel(),cause);
			}
		});
	}
}
