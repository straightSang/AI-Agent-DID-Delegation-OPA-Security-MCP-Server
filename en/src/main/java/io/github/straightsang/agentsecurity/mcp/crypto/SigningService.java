package io.github.straightsang.agentsecurity.mcp.crypto;

/** Abstraction for signing approval tokens, responses, and ledger checkpoints. */
public interface SigningService {
    String algorithm();
    byte[] sign(byte[] message);
    boolean verify(byte[] message, byte[] signature);
}
