package fr.esgi.rent.beans;

import fr.esgi.rent.beans.PropertyType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.EnumSource.Mode.MATCH_ALL;

class PropertyTypeTest {

    @ParameterizedTest
    @EnumSource(value = PropertyType.class, mode = MATCH_ALL)
    void shouldGetByDesignation(PropertyType propertyType) {
        Optional<PropertyType> optionalPropertyType = PropertyType.getByDesignation(propertyType.getDesignation());

        assertThat(optionalPropertyType).hasValue(propertyType);
    }

    @Test
    void givenUnknownDesignation_shouldReturnOptionalEmpty() {
        assertThat(PropertyType.getByDesignation("unknown")).isEmpty();
    }

}
