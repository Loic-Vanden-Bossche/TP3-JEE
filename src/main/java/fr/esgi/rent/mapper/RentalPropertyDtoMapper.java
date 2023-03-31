package fr.esgi.rent.mapper;

import fr.esgi.rent.beans.RentalProperty;
import fr.esgi.rent.dto.RentalPropertyDto;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;

@ApplicationScoped
public class RentalPropertyDtoMapper {

    public List<RentalPropertyDto> mapToDtoList(List<RentalProperty> rentalProperties) {
        return rentalProperties.stream()
                .map(this::mapToDto)
                .toList();
    }

    public RentalPropertyDto mapToDto(RentalProperty rentalProperty) {
        return new RentalPropertyDto(
                rentalProperty.description(),
                rentalProperty.address(),
                rentalProperty.town(),
                rentalProperty.propertyType(),
                rentalProperty.rentAmount(),
                rentalProperty.securityDepositAmount(),
                rentalProperty.area());
    }

}
