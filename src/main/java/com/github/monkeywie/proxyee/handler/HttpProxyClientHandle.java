package com.github.monkeywie.proxyee.handler;


import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.util.ReferenceCountUtil;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.babagilo.proxy.BabagiloProxyHandler;

public class HttpProxyClientHandle extends ChannelInboundHandlerAdapter {
	Logger logger = Logger.getLogger(BabagiloProxyHandler.class.getName());
  private Channel clientChannel;

  public HttpProxyClientHandle(Channel clientChannel) {
    this.clientChannel = clientChannel;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    //客户端channel已关闭则不转发了
    if (!clientChannel.isOpen()) {
      ReferenceCountUtil.release(msg);
      return;
    }
    HttpProxyInterceptPipeline interceptPipeline = ((BabagiloProxyHandler) clientChannel.pipeline()
        .get("serverHandle")).getInterceptPipeline();
    if (msg instanceof HttpResponse) {
      interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpResponse) msg);
    } else if (msg instanceof HttpContent) {
      interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpContent) msg);
    } else {
      clientChannel.writeAndFlush(msg);
    }
  }

  @Override
  public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
    ctx.channel().close();
    clientChannel.close();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
    ctx.channel().close();
    clientChannel.close();
    logger.log(Level.FINE, "53 Execption happening on channel "+ctx.channel(),cause);
  }
}
