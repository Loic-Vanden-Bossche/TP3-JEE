package fr.esgi.rent.samples;

import fr.esgi.rent.dto.RentalPropertyDto;

import java.util.List;

import static fr.esgi.rent.beans.PropertyType.FLAT;
import static fr.esgi.rent.beans.PropertyType.HOUSE;

public class RentalPropertyDtoSample {

    public static List<RentalPropertyDto> rentalPropertyDtoList() {
        RentalPropertyDto rentalProperty = oneRentalPropertyDto();

        RentalPropertyDto largeFlat = new RentalPropertyDto(
                "Appartement bien situé près du métro et des commerces",
                "90 rue de la Victoire",
                "Neuilly-sur-Seine",
                FLAT,
                1040.90,
                1250.90,
                50.69);

        RentalPropertyDto house = new RentalPropertyDto(
                "Maison à louer dans banlieue calme et proche du RER",
                "12 rue de la Pyramide",
                "Champs-sur-Marne",
                HOUSE,
                1050.90,
                1400.90,
                62.50);

        return List.of(rentalProperty, largeFlat, house);
    }

    public static RentalPropertyDto oneRentalPropertyDto() {
        return new RentalPropertyDto(
                "Appartement spacieux avec vue sur l'ESGI",
                "77 Rue des roses",
                "Paris",
                FLAT,
                750.90,
                1200.90,
                37.48);
    }

}
