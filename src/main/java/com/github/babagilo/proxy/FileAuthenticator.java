package com.github.babagilo.proxy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.stream.Stream;

public class FileAuthenticator extends Authenticator{
	Stream<String> lines;
	public FileAuthenticator(File authFile) throws IOException {
		lines = Files.lines(authFile.toPath());
	}

	@Override
	public boolean authenticate(String s) {
		return lines.anyMatch(line -> line.equals(s));
	}

}
