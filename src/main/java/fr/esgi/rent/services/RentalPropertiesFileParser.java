package fr.esgi.rent.services;

import fr.esgi.rent.beans.RentalProperty;
import fr.esgi.rent.exception.MalFormattedRentalPropertiesResourceUriException;
import fr.esgi.rent.exception.RentalPropertiesParsingException;
import fr.esgi.rent.exception.RentalPropertiesResourceNotFoundException;
import jakarta.enterprise.context.ApplicationScoped;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static fr.esgi.rent.csv.CsvProperties.HEADERS;

@ApplicationScoped
public class RentalPropertiesFileParser {

    public List<RentalProperty> parse(String filename) {
        URL resource = getClass().getClassLoader().getResource(filename);

        if (resource == null) {
            throw new RentalPropertiesResourceNotFoundException(filename + " n'a pas été trouvé");
        }

        CSVFormat csvFormat = CSVFormat.DEFAULT.builder()
                .setHeader(HEADERS)
                .setSkipHeaderRecord(true)
                .build();

        try (BufferedReader bufferedReader = Files.newBufferedReader(Paths.get(resource.toURI()));
             CSVParser parser = new CSVParser(bufferedReader, csvFormat)) {

            return parser.stream()
                    .filter(csvRecord -> csvRecord.size() == HEADERS.length)
                    .map((CSVRecord csvRecord) -> RentalProperty.create(csvRecord, HEADERS, csvField -> csvField.equals("oui")))
                    .toList();

        } catch (URISyntaxException e) {
            throw new MalFormattedRentalPropertiesResourceUriException("L'URI du fichier " + filename + " est invalide", e);
        } catch (IOException e) {
            throw new RentalPropertiesParsingException("Une erreur a eu lieu durant le parsing du fichier " + filename, e);
        }
    }

}
