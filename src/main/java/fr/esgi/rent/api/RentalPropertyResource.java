package fr.esgi.rent.api;

import fr.esgi.rent.beans.RentalProperty;
import fr.esgi.rent.dto.RentalPropertyDto;
import fr.esgi.rent.exception.NotFoundRentalPropertyException;
import fr.esgi.rent.mapper.RentalPropertyDtoMapper;
import fr.esgi.rent.services.RentalPropertiesFileParser;
import jakarta.inject.Inject;
import jakarta.validation.constraints.Positive;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

import java.util.List;

@Path("/rental-properties")
public class RentalPropertyResource {

    private final RentalPropertiesFileParser rentalPropertiesFileParser;
    private final RentalPropertyDtoMapper rentalPropertyDtoMapper;

    @Inject
    public RentalPropertyResource(RentalPropertiesFileParser rentalPropertiesFileParser,
                                  RentalPropertyDtoMapper rentalPropertyDtoMapper) {
        this.rentalPropertiesFileParser = rentalPropertiesFileParser;
        this.rentalPropertyDtoMapper = rentalPropertyDtoMapper;
    }

    @GET
    public List<RentalPropertyDto> getRentalProperties() {
        List<RentalProperty> rentalProperties = rentalPropertiesFileParser.parse("rentalProperties.csv");

        return rentalPropertyDtoMapper.mapToDtoList(rentalProperties);
    }

    @GET
    @Path("/{id}")
    public RentalPropertyDto getRentalProperty(@PathParam("id") @Positive int id) {
        return rentalPropertiesFileParser.parse("rentalProperties.csv")
                .stream()
                .filter(rentalProperty -> rentalProperty.referenceId() == id)
                .map(rentalPropertyDtoMapper::mapToDto)
                .findAny()
                .orElseThrow(() -> new NotFoundRentalPropertyException("RentalProperty not found with id " + id));
    }
}