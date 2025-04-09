package main

import (
	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/gofiber/fiber/v2"
	"log"
	"strings"
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

// CasbinMiddleware creates a middleware for role-based access control
// CasbinMiddleware creates a middleware for role-based access control
func CasbinMiddleware(enforcer *casbin.Enforcer) fiber.Handler {
	return func(c *fiber.Ctx) error {
		enforcer.LoadPolicy()
		var identifier string
		// Extract userID or adminID from context based on path
		path := c.Path()

		if strings.Contains(path, "admin") {
			log.Println("admin path detected")
			roleRequest := RoleRequest{}
			err := c.BodyParser(&roleRequest)
			if err != nil {
				return c.Status(400).JSON(DefaultResponse{
					Status:  "error",
					Message: "Invalid request body",
					Data:    nil,
				})
			}
			log.Println(roleRequest)
			identifier = roleRequest.AdminID

			if identifier == "" {
				return c.Status(400).JSON(DefaultResponse{
					Status:  "error",
					Message: "Admin ID not provided or invalid",
					Data:    nil,
				})
			}
			log.Println("admin id:", identifier)
		} else {
			identifier = c.Params("userId")

			if identifier == "" {
				identifier = c.Query("user_id")
				if identifier == "" {
					return c.Status(400).JSON(DefaultResponse{
						Status:  "error",
						Message: "User ID not provided or invalid",
						Data:    nil,
					})
				}
			}
			log.Println("user ID is:", identifier)
		}

		// Get the user's roles from Casbin
		roles, err := enforcer.GetRolesForUser(identifier)
		log.Println("roles are:", roles)

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
		log.Println(resource)
		method := c.Method()
		log.Println(method)

		// Try each role the user has until we find one that has permission
		hasPermission := false
		for _, role := range roles {
			log.Println("role is:", role)
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

		return c.Next()
	}
}
