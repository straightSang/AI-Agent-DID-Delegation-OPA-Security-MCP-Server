package io.github.straightsang.agentsecurity.mcp.exception;

/** Indicates a system or cryptographic configuration failure during command-signature verification. */
public class CommandIntegrityVerificationException extends RuntimeException {
    public CommandIntegrityVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
