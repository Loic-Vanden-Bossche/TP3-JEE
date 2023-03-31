package fr.esgi.rent.beans;

import java.util.Arrays;
import java.util.Optional;

public enum PropertyType {
    FLAT("Appartement"),
    HOUSE("Maison");
	
    PropertyType(String designation) {
		this.designation = designation;
	}

	private final String designation;

    public String getDesignation() {
		return designation;
	}

	public static Optional<PropertyType> getByDesignation(String designation) {
        return Arrays.stream(values())
                .filter(propertyType -> propertyType.designation.equals(designation))
                .findAny();
    }

}
