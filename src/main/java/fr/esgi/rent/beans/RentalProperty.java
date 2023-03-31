package fr.esgi.rent.beans;

import org.apache.commons.csv.CSVRecord;

import java.util.function.Predicate;

import static fr.esgi.rent.beans.PropertyType.FLAT;

public record RentalProperty(
        int referenceId,
        String description,
        String town,
        String address,
        PropertyType propertyType,
        double rentAmount,
        double securityDepositAmount,
        double area,
        int bedroomsCount,
        int floorNumber,
        int numberOfFloors,
        int constructionYear,
        EnergyClassification energyClassification,
        boolean hasElevator,
        boolean hasIntercom,
        boolean hasBalcony,
        boolean hasParkingSpace) {

    public static RentalProperty create(CSVRecord csvRecord, String[] headers, Predicate<String> testIfCsvFieldHasExpectedValue) {
        PropertyType propertyType = PropertyType.getByDesignation(csvRecord.get(headers[4])).orElse(null);

        return new RentalProperty(
                Integer.parseInt(csvRecord.get(headers[0])),
                csvRecord.get(headers[1]),
                csvRecord.get(headers[2]),
                csvRecord.get(headers[3]),
                propertyType,
                Double.parseDouble(csvRecord.get(headers[5])),
                Double.parseDouble(csvRecord.get(headers[6])),
                Double.parseDouble(csvRecord.get(headers[7])),
                Integer.parseInt(csvRecord.get(headers[8])),
                getFloorNumber(propertyType, csvRecord, headers),
                getNumberOfFloors(propertyType, csvRecord, headers),
                Integer.parseInt(csvRecord.get(headers[11])),
                EnergyClassification.getByName(csvRecord.get(headers[12])).orElse(null),
                testIfCsvFieldHasExpectedValue.test(csvRecord.get(headers[13])),
                testIfCsvFieldHasExpectedValue.test(csvRecord.get(headers[14])),
                testIfCsvFieldHasExpectedValue.test(csvRecord.get(headers[15])),
                testIfCsvFieldHasExpectedValue.test(csvRecord.get(headers[16])));
    }

    private static int getFloorNumber(PropertyType propertyType, CSVRecord csvRecord, String[] headers) {
        if (FLAT.equals(propertyType)) {
            return Integer.parseInt(csvRecord.get(headers[9]));
        }
        return 0;
    }

    private static int getNumberOfFloors(PropertyType propertyType, CSVRecord csvRecord, String[] headers) {
        if (FLAT.equals(propertyType)) {
            return Integer.parseInt(csvRecord.get(headers[10]));
        }
        return 0;
    }

}
