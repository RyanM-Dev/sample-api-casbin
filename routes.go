package main

import "github.com/gofiber/fiber/v2"

func (h *APIHandlers) RegisterRoutes(app *fiber.App) {
	// Create API group
	api := app.Group("/api/" + h.APIGroup)
	// User management routes
	api.Post("/users", h.CreateUser())
	api.Use(CasbinMiddleware(h.Enforcer))
	api.Get("/users/:userId", h.GetUsers())

	// RBAC management route
	api.Post("/admin", h.ManageRoles())

	// Data routes
	api.Get("/normal-data", h.ReadNormalData())
	api.Post("/normal-data", h.WriteNormalData())
	api.Get("/secret-data", h.ReadSecretData())
	api.Post("/secret-data", h.WriteSecretData())
}
