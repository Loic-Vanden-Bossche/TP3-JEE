package fr.esgi.rent.mapper;

import fr.esgi.rent.beans.RentalProperty;
import fr.esgi.rent.dto.RentalPropertyDto;
import fr.esgi.rent.mapper.RentalPropertyDtoMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static fr.esgi.rent.beans.PropertyType.FLAT;
import static fr.esgi.rent.samples.RentalPropertyDtoSample.rentalPropertyDtoList;
import static fr.esgi.rent.samples.RentalPropertySample.oneRentalProperty;
import static fr.esgi.rent.samples.RentalPropertySample.rentalProperties;
import static org.assertj.core.api.Assertions.assertThat;

class RentalPropertyDtoMapperTest {

    @Test
    void shouldMapToDtoList() {
        List<RentalProperty> rentalProperties = rentalProperties();
        List<RentalPropertyDto> expectedRentalPropertyDtoList = rentalPropertyDtoList();

        RentalPropertyDtoMapper rentalPropertyDtoMapper = new RentalPropertyDtoMapper();

        List<RentalPropertyDto> rentalPropertyDtoList = rentalPropertyDtoMapper.mapToDtoList(rentalProperties);

        assertThat(rentalPropertyDtoList).containsExactlyInAnyOrderElementsOf(expectedRentalPropertyDtoList);
    }

    @Test
    void shouldMapToDto() {
        RentalProperty rentalProperty = oneRentalProperty();

        RentalPropertyDtoMapper rentalPropertyDtoMapper = new RentalPropertyDtoMapper();

        RentalPropertyDto rentalPropertyDto = rentalPropertyDtoMapper.mapToDto(rentalProperty);

        assertThat(rentalPropertyDto.description()).isEqualTo("Appartement spacieux avec vue sur l'ESGI");
        assertThat(rentalPropertyDto.address()).isEqualTo("77 Rue des roses");
        assertThat(rentalPropertyDto.town()).isEqualTo("Paris");
        assertThat(rentalPropertyDto.propertyType()).isEqualTo(FLAT);
        assertThat(rentalPropertyDto.rentAmount()).isEqualTo(750.90);
        assertThat(rentalPropertyDto.securityDepositAmount()).isEqualTo(1200.90);
        assertThat(rentalPropertyDto.area()).isEqualTo(37.48);
    }

}
