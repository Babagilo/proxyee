package com.github.monkeywie.proxyee;

import com.github.babagilo.proxy.BabagiloProxy;
import com.github.babagilo.proxy.BabagiloProxyConfig;

public class HandelSslHttpProxyServer {

  public static void main(String[] args) throws Exception {
    BabagiloProxyConfig config =  new BabagiloProxyConfig("localhost", 9999,true);

    new BabagiloProxy(config).run();
  }
}
