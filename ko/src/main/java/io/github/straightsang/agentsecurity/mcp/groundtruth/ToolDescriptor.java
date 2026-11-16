package io.github.straightsang.agentsecurity.mcp.groundtruth;

/* 도구 하나의 이름, 설명, 코드 해시, 게시자다. 설명은 LLM이 읽는 입력이므로 변조되면 인젝션 경로가 된다. */
public record ToolDescriptor(String name, String description, String codeDigest, String publisher) {
}
