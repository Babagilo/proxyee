package com.github.babagilo.auth;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.stream.Collectors;

import io.netty.handler.codec.http.HttpRequest;

public class FileAuthorizer extends Authorizer {
	private List<String> authzList;

	public FileAuthorizer(File authzFile) throws IOException {
		authzList = Files.lines(authzFile.toPath()).collect(Collectors.toList());
	}

	@Override
	public boolean allowAccess(HttpRequest httpRequest) {
		String uri = httpRequest.uri();

		System.out.println("22 URI : " + uri);
		return authzList.contains(uri);
	}
}
