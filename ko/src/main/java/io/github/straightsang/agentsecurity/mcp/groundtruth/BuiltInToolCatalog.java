package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.service.CalculatorService;
import io.github.straightsang.agentsecurity.mcp.service.LabDocumentService;
import io.github.straightsang.agentsecurity.mcp.tools.CalculatorTools;
import io.github.straightsang.agentsecurity.mcp.tools.LabDocumentTools;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.stereotype.Component;

/*
 * 이 서버가 노출하는 도구의 이름, 설명, 코드 해시를 @McpTool 선언과 실제 클래스 파일에서 읽어 온다.
 * 설명 문자열을 따로 복사해 두지 않으므로 코드와 계보 기록이 어긋나지 않는다.
 * 코드 해시는 도구 클래스와 그 도구가 호출하는 서비스 클래스의 .class 바이트를 이어 붙여 계산한다.
 */
@Component
public class BuiltInToolCatalog {
    public static final String PUBLISHER = "local";

    public List<ToolDescriptor> descriptors() {
        List<ToolDescriptor> result = new ArrayList<>();
        collect(CalculatorTools.class, CalculatorService.class, result);
        collect(LabDocumentTools.class, LabDocumentService.class, result);
        return List.copyOf(result);
    }

    private void collect(Class<?> toolClass, Class<?> serviceClass, List<ToolDescriptor> out) {
        String digest = combinedDigest(toolClass, serviceClass);
        for (Method method : toolClass.getDeclaredMethods()) {
            McpTool annotation = method.getAnnotation(McpTool.class);
            if (annotation == null) continue;
            String name = annotation.name().isBlank() ? method.getName() : annotation.name();
            out.add(new ToolDescriptor(name, annotation.description(), digest, PUBLISHER));
        }
    }

    static String combinedDigest(Class<?>... classes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Class<?> type : classes) {
                digest.update(classBytes(type));
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception exception) {
            throw new IllegalStateException("도구 코드 해시를 계산하지 못했습니다.", exception);
        }
    }

    private static byte[] classBytes(Class<?> type) throws IOException {
        try (InputStream input = type.getResourceAsStream(type.getSimpleName() + ".class")) {
            if (input == null) return type.getName().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return input.readAllBytes();
        }
    }
}
