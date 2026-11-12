package io.github.straightsang.agentsecurity.mcp.exception;

/** 명령 전자서명 검증 중 시스템 또는 암호화 설정 문제가 발생했음을 나타낸다. */
public class CommandIntegrityVerificationException extends RuntimeException {
    public CommandIntegrityVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
