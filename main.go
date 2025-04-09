package main

import (
	"github.com/gofiber/fiber/v2"
	"log"
)

//3 end point for 3 role, user,employee,manager
//2 api version as a representation for different domain(company,section,....)
//employee has read access to important access and write and read to normal data
//admin has read and write access to imp data
//user has only read access to normal data
//middleware to check role and permissions

func main() {
	app := fiber.New()
	enforcer, err := SetupCasbin()
	if err != nil {
		panic(err)
	}
	dataStore := NewDataStore()
	ryanCompanyHandlers := NewAPIHandlers(enforcer, dataStore, "RyanCompany")
	ahmadCompanyHandlers := NewAPIHandlers(enforcer, dataStore, "AhmadCompany")

	// Register routes for each API group
	ryanCompanyHandlers.RegisterRoutes(app)
	ahmadCompanyHandlers.RegisterRoutes(app)

	// Start server
	log.Fatal(app.Listen(":3000"))

}
