package com.github.babagilo.auth;

import io.netty.handler.codec.http.HttpRequest;

public abstract class Authorizer {

	private static Authorizer surepassAuthorizer = new Authorizer() {

		@Override
		public boolean allowAccess(HttpRequest request) {
			return true;
		}};


	public static Authorizer getSurepassAuthorizer() {
		return surepassAuthorizer ;
	}
	
	public abstract boolean allowAccess(HttpRequest request);

}
