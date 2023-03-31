package fr.esgi.rent.services;

import fr.esgi.rent.beans.RentalProperty;
import fr.esgi.rent.exception.RentalPropertiesResourceNotFoundException;
import fr.esgi.rent.samples.RentalPropertySample;
import fr.esgi.rent.services.RentalPropertiesFileParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class RentalPropertyFileParserTest {

    @Test
    void shouldParse() {
        List<RentalProperty> expectedRentalProperties = RentalPropertySample.rentalProperties();

        RentalPropertiesFileParser rentalPropertiesFileParser = new RentalPropertiesFileParser();

        List<RentalProperty> rentalProperties = rentalPropertiesFileParser.parse("rentalProperties.csv");

        assertThat(rentalProperties).containsExactlyInAnyOrderElementsOf(expectedRentalProperties);
    }

    @Test
    void givenUnknownFilename_shouldThrowRentalPropertiesResourceNotFoundException() {
        RentalPropertiesFileParser rentalPropertiesFileParser = new RentalPropertiesFileParser();

        assertThatExceptionOfType(RentalPropertiesResourceNotFoundException.class)
                .isThrownBy(() -> rentalPropertiesFileParser.parse("unknownFile.csv"))
                .satisfies(e -> assertThat(e.getMessage()).isEqualTo("unknownFile.csv n'a pas été trouvé"));
    }

}
