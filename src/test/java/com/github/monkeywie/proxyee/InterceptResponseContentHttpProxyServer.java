package com.github.monkeywie.proxyee;

import java.nio.charset.Charset;

import com.github.babagilo.proxy.BabagiloProxy;
import com.github.babagilo.proxy.ProxyMode;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.FullResponseIntercept;
import com.github.monkeywie.proxyee.util.HttpUtil;

import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

public class InterceptResponseContentHttpProxyServer {

  public static void main(String[] args) throws Exception {

    new BabagiloProxy()
        .proxyInterceptInitializer(new HttpProxyInterceptInitializer() {
          @Override
          public void init(HttpProxyInterceptPipeline pipeline) {
            pipeline.addLast(new FullResponseIntercept() {

              @Override
              public boolean match(HttpRequest httpRequest, HttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                //在匹配到百度首页时插入js
                return HttpUtil.checkUrl(pipeline.getHttpRequest(), "^www.baidu.com$")
                    && isHtml(httpRequest, httpResponse);
              }

              @Override
              public void handelResponse(HttpRequest httpRequest, FullHttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                //打印原始响应信息
                System.out.println(httpResponse.toString());
                System.out.println(httpResponse.content().toString(Charset.defaultCharset()));
                //修改响应头和响应体
                httpResponse.headers().set("handel", "edit head");
                /*int index = ByteUtil.findText(httpResponse.content(), "<head>");
                ByteUtil.insertText(httpResponse.content(), index, "<script>alert(1)</script>");*/
                httpResponse.content().writeBytes("<script>alert('hello proxyee')</script>".getBytes());
              }
            });
          }
        })
        .run(9999);
  }
}
