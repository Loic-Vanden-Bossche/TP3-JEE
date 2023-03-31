package fr.esgi.rent.api;

import fr.esgi.rent.api.RentalPropertyResource;
import fr.esgi.rent.beans.RentalProperty;
import fr.esgi.rent.dto.RentalPropertyDto;
import fr.esgi.rent.exception.NotFoundRentalPropertyException;
import fr.esgi.rent.mapper.RentalPropertyDtoMapper;
import fr.esgi.rent.services.RentalPropertiesFileParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static fr.esgi.rent.beans.EnergyClassification.D;
import static fr.esgi.rent.beans.PropertyType.FLAT;
import static fr.esgi.rent.samples.RentalPropertyDtoSample.oneRentalPropertyDto;
import static fr.esgi.rent.samples.RentalPropertyDtoSample.rentalPropertyDtoList;
import static fr.esgi.rent.samples.RentalPropertySample.rentalProperties;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RentalPropertyResourceTest {

    @InjectMocks
    private RentalPropertyResource rentalPropertyResource;

    @Mock
    private RentalPropertiesFileParser rentalPropertiesFileParser;

    @Mock
    private RentalPropertyDtoMapper rentalPropertyDtoMapper;

    @Test
    void shouldGetRentalProperties() {
        List<RentalPropertyDto> expectedRentalPropertyDtoList = rentalPropertyDtoList();
        List<RentalProperty> rentalProperties = rentalProperties();

        when(rentalPropertiesFileParser.parse("rentalProperties.csv")).thenReturn(rentalProperties);
        when(rentalPropertyDtoMapper.mapToDtoList(rentalProperties)).thenReturn(expectedRentalPropertyDtoList);

        List<RentalPropertyDto> rentalPropertyDtoList = rentalPropertyResource.getRentalProperties();

        assertThat(rentalPropertyDtoList).containsExactlyInAnyOrderElementsOf(expectedRentalPropertyDtoList);

        verify(rentalPropertiesFileParser).parse("rentalProperties.csv");
        verify(rentalPropertyDtoMapper).mapToDtoList(rentalProperties);

        verifyNoMoreInteractions(rentalPropertiesFileParser, rentalPropertyDtoMapper);
    }

    @Test
    void shouldGetRentalProperty() {
        List<RentalProperty> rentalProperties = rentalProperties();
        RentalProperty rentalProperty = rentalProperty();
        RentalPropertyDto expectedRentalPropertyDto = oneRentalPropertyDto();

        when(rentalPropertiesFileParser.parse("rentalProperties.csv")).thenReturn(rentalProperties);
        when(rentalPropertyDtoMapper.mapToDto(rentalProperty)).thenReturn(expectedRentalPropertyDto);

        RentalPropertyDto rentalPropertyDto = rentalPropertyResource.getRentalProperty(46890);

        assertThat(rentalPropertyDto).isEqualTo(expectedRentalPropertyDto);

        verify(rentalPropertiesFileParser).parse("rentalProperties.csv");
        verify(rentalPropertyDtoMapper).mapToDto(rentalProperty);

        verifyNoMoreInteractions(rentalPropertiesFileParser, rentalPropertyDtoMapper);
    }

    @Test
    void givenNonExistentId_shouldThrowNotFoundRentalPropertyException() {
        List<RentalProperty> rentalProperties = rentalProperties();

        when(rentalPropertiesFileParser.parse("rentalProperties.csv")).thenReturn(rentalProperties);

        assertThatExceptionOfType(NotFoundRentalPropertyException.class)
                .isThrownBy(() -> rentalPropertyResource.getRentalProperty(4690))
                .satisfies(e -> assertThat(e.getMessage()).isEqualTo("RentalProperty not found with id 4690"));

        verify(rentalPropertiesFileParser).parse("rentalProperties.csv");

        verifyNoInteractions(rentalPropertyDtoMapper);
        verifyNoMoreInteractions(rentalPropertiesFileParser);
    }

    private RentalProperty rentalProperty() {
        return new RentalProperty(
                46890,
                "Appartement spacieux avec vue sur l'ESGI",
                "Paris",
                "77 Rue des roses",
                FLAT,
                750.90,
                1200.90,
                37.48,
                2,
                1,
                3,
                1990,
                D,
                false,
                false,
                true,
                false);
    }

}
