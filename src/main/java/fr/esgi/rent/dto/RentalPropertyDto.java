package fr.esgi.rent.dto;

import fr.esgi.rent.beans.PropertyType;

public record RentalPropertyDto(String description,
                                String address,
                                String town,
                                PropertyType propertyType,
                                double rentAmount,
                                double securityDepositAmount,
                                double area) {
}
