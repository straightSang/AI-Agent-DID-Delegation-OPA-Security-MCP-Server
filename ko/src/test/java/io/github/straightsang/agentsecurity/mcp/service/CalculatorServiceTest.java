package io.github.straightsang.agentsecurity.mcp.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class CalculatorServiceTest {

    private final CalculatorService service = new CalculatorService();

    @Test
    void addsTwoIntegers() {
        assertThat(service.add(1, 2)).isEqualTo(3);
    }

    @Test
    void rejectsIntegerOverflow() {
        assertThatThrownBy(() -> service.add(Integer.MAX_VALUE, 1))
                .isInstanceOf(ArithmeticException.class);
    }
}

