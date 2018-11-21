package com.github.monkeywie.proxyee;

import com.github.babagilo.proxy.BabagiloProxy;
import com.github.babagilo.proxy.BabagiloProxyConfig;

public class HandelSslHttpProxyServer {

  public static void main(String[] args) throws Exception {
    BabagiloProxyConfig config =  new BabagiloProxyConfig();
    config.setPort(9999);
    config.setHandleSsl(true);
    new BabagiloProxy(config).run();
  }
}
