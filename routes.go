package main

import "github.com/gofiber/fiber/v2"

func (h *APIHandlers) RegisterRoutes(app *fiber.App) {
	// Create API group
	api := app.Group("/api/" + h.APIGroup)
	// User management routes
	api.Post("/users", h.CreateUser())
	api.Post("/admin", CasbinAdminMiddleware(h.Enforcer), h.ManageRoles())
	api.Get("/users/:userId", CasbinAdminMiddleware(h.Enforcer), h.GetUsers())

	// RBAC management route

	// Data routes
	api.Get("/normal-data", CasbinMiddleware(h.Enforcer), h.ReadNormalData())
	api.Post("/normal-data", CasbinMiddleware(h.Enforcer), h.WriteNormalData())
	api.Get("/secret-data", CasbinMiddleware(h.Enforcer), h.ReadSecretData())
	api.Post("/secret-data", CasbinAdminMiddleware(h.Enforcer), h.WriteSecretData())
}
