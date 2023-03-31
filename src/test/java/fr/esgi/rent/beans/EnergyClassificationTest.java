package fr.esgi.rent.beans;

import fr.esgi.rent.beans.EnergyClassification;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.EnumSource.Mode.MATCH_ALL;

class EnergyClassificationTest {

    @ParameterizedTest
    @EnumSource(value = EnergyClassification.class, mode = MATCH_ALL)
    void shouldGetByName(EnergyClassification energyClassification) {
        Optional<EnergyClassification> optionalEnergyClassification = EnergyClassification.getByName(energyClassification.name());

        assertThat(optionalEnergyClassification).hasValue(energyClassification);
    }

    @Test
    void givenUnknownName_shouldReturnOptionalEmpty() {
        assertThat(EnergyClassification.getByName("unknown")).isEmpty();
    }

}
