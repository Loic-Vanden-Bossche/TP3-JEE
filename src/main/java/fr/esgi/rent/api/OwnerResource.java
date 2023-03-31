package fr.esgi.rent.api;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import java.util.List;

@Path("/owners")
public class OwnerResource {

    @GET
    public List<String> getOwners() {
        return List.of("Jean-Claude Dupont", "Guillaume Dupond", "Robert Lopez");
    }

}
