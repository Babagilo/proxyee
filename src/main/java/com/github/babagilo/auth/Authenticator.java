package com.github.babagilo.auth;

public abstract class Authenticator {
	private static Authenticator surepassAuthenticator = new Authenticator() {
		@Override
		public boolean authenticate(String s) {
			return true;
		}
		
	};
	
	public abstract boolean authenticate(String s);
	
	public static Authenticator getSurepassAuthenticator() {
		return surepassAuthenticator;
	}
}
