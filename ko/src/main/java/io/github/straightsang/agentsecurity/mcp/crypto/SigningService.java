package io.github.straightsang.agentsecurity.mcp.crypto;

/** 서버가 승인 토큰·응답·원장 체크포인트에 전자서명하는 추상화다. */
public interface SigningService {
    String algorithm();
    byte[] sign(byte[] message);
    boolean verify(byte[] message, byte[] signature);
}
