package com.github.babagilo.auth;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.stream.Collectors;

public class FileAuthenticator extends Authenticator{

	private List<String> upList;

	public FileAuthenticator(File authFile) throws IOException {
		upList = Files.lines(authFile.toPath()).collect(Collectors.toList());
	}

	@Override
	/**
	 * s - base64(username password)
	 */
	public boolean authenticate(String s) {
		return upList.contains(s);
	}

}
