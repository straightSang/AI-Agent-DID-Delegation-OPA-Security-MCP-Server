package io.github.straightsang.agentsecurity.mcp.ensemble;

/* 증거 묶음을 보고 위험 수준을 판정하는 탐지기다. 판정이 결정이 아니라 한 표라는 점이 중요하다. */
public interface Detector {
    String id();

    DetectorResult assess(EvidencePacket packet);
}
