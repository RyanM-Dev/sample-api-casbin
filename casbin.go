package main

import (
	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/gofiber/fiber/v2"
	"log"
)

// SetupCasbin initializes the Casbin enforcer with the model and policy files
func SetupCasbin() (*casbin.Enforcer, error) {
	adapter := fileadapter.NewAdapter("policy.csv")
	enforcer, err := casbin.NewEnforcer("model.conf", adapter)
	if err != nil {
		return nil, err
	}

	// Load the policy from DB
	err = enforcer.LoadPolicy()
	if err != nil {
		return nil, err
	}
	policies, _ := enforcer.GetPolicy()
	groupPolicies, _ := enforcer.GetGroupingPolicy()
	log.Printf("Loaded policy: %v", policies)
	log.Printf("Loaded role definitions: %v", groupPolicies)

	return enforcer, nil
}

func CasbinAdminMiddleware(enforcer *casbin.Enforcer) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get admin ID from the header
		adminID := c.Get("X-Admin-ID")
		if adminID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing admin ID in request header",
			})
		}

		roles, err := enforcer.GetRolesForUser(adminID)
		if err != nil {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "500",
				Message: "can't find roles",
				Data:    nil,
			})
		}

		if len(roles) == 0 {
			return c.Status(403).JSON(DefaultResponse{
				Status:  "error",
				Message: "User has no assigned roles",
			})
		}

		endpoint := c.Path()
		isValid := false
		for _, role := range roles {
			isAllowed, err := enforcer.Enforce(role, endpoint, c.Method())
			if err != nil {
				continue
			}
			if isAllowed {
				isValid = true
				break
			}
		}

		if !isValid {
			return c.Status(403).JSON(DefaultResponse{
				Status:  "error",
				Message: "Insufficient permissions for this operation",
			})
		}

		// Set the admin ID in locals for the next handler
		c.Locals("adminID", adminID)
		return c.Next()
	}
}

func CasbinMiddleware(enforcer *casbin.Enforcer) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user ID from the header
		userID := c.Get("X-User-ID")
		if userID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing user ID in request header",
			})
		}

		roles, err := enforcer.GetRolesForUser(userID)
		if err != nil {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "500",
				Message: "can't find roles",
				Data:    nil,
			})
		}

		if len(roles) == 0 {
			return c.Status(403).JSON(DefaultResponse{
				Status:  "error",
				Message: "User has no assigned roles",
				Data:    nil,
			})
		}

		// Check if any of the user's roles has permission for this resource and method
		resource := c.Path()
		method := c.Method()

		// Try each role the user has until we find one that has permission
		hasPermission := false
		for _, role := range roles {
			allowed, err := enforcer.Enforce(role, resource, method)
			if err != nil {
				continue // If error, try next role
			}

			if allowed {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			return c.Status(403).JSON(DefaultResponse{
				Status:  "error",
				Message: "Insufficient permissions for this operation",
				Data:    nil,
			})
		}

		// Set the user ID in locals for the next handler
		c.Locals("userID", userID)
		return c.Next()
	}
}
