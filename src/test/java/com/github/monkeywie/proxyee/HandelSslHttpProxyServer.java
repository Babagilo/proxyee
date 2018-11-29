package com.github.monkeywie.proxyee;

import com.github.babagilo.proxy.BabagiloProxy;
import com.github.babagilo.proxy.ProxyMode;

public class HandelSslHttpProxyServer {

  public static void main(String[] args) throws Exception {
    new BabagiloProxy(ProxyMode.INTERCEPT).run(9999);
  }
}
