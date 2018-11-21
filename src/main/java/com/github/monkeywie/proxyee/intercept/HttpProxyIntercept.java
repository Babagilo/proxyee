package com.github.monkeywie.proxyee.intercept;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

public class HttpProxyIntercept {

  /**
   * 拦截代理服务器到目标服务器的请求头
   * Intercept the request header of Proxy-->Origin
   */
  public void beforeRequest(Channel clientChannel, HttpRequest httpRequest,
      HttpProxyInterceptPipeline pipeline) throws Exception {
    pipeline.beforeRequest(clientChannel, httpRequest);
  }

  /**
   * 拦截代理服务器到目标服务器的请求体
   * Intercept the request body of Proxy --> Origin
   */
  public void beforeRequest(Channel clientChannel, HttpContent httpContent,
      HttpProxyInterceptPipeline pipeline) throws Exception {
    pipeline.beforeRequest(clientChannel, httpContent);
  }

  /**
   * 拦截代理服务器到客户端的响应头
   * Intercept the response header of Client <-- Proxy
   */
  public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
      HttpProxyInterceptPipeline pipeline) throws Exception {
    pipeline.afterResponse(clientChannel, proxyChannel, httpResponse);
  }


  /**
   * 拦截代理服务器到客户端的响应体
   * Intercept the response body of Client <-- Proxy
   */
  public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
      HttpProxyInterceptPipeline pipeline)
      throws Exception {
    pipeline.afterResponse(clientChannel, proxyChannel, httpContent);
  }
}
