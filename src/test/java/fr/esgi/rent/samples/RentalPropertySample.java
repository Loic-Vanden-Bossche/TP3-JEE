package fr.esgi.rent.samples;

import fr.esgi.rent.beans.RentalProperty;

import java.util.List;

import static fr.esgi.rent.beans.EnergyClassification.B;
import static fr.esgi.rent.beans.EnergyClassification.D;
import static fr.esgi.rent.beans.PropertyType.FLAT;
import static fr.esgi.rent.beans.PropertyType.HOUSE;

public class RentalPropertySample {

    public static List<RentalProperty> rentalProperties() {
        RentalProperty rentalProperty = new RentalProperty(
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

        RentalProperty largeFlat = new RentalProperty(
                12850,
                "Appartement bien situé près du métro et des commerces",
                "Neuilly-sur-Seine",
                "90 rue de la Victoire",
                FLAT,
                1040.90,
                1250.90,
                50.69,
                3,
                2,
                5,
                1989,
                B,
                true,
                true,
                true,
                true);

        RentalProperty house = new RentalProperty(
                83872,
                "Maison à louer dans banlieue calme et proche du RER",
                "Champs-sur-Marne",
                "12 rue de la Pyramide",
                HOUSE,
                1050.90,
                1400.90,
                62.50,
                4,
                0,
                0,
                2000,
                B,
                false,
                false,
                false,
                false);

        return List.of(rentalProperty, largeFlat, house);
    }

    public static RentalProperty oneRentalProperty() {
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
                true,
                true,
                true,
                true);
    }

}

