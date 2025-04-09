package main

import (
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/gofiber/fiber/v2"
)

// DefaultResponse represents a standard JSON response
type DefaultResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// UserRequest includes user ID, name and roles for creation
type UserRequest struct {
	UserID string   `json:"user_id"`
	Name   string   `json:"name"`
	Roles  []string `json:"roles"` // Multiple roles: "user", "employee", "admin"
}

// DataRequest includes only data for operations (no UserID needed as it's in header)
type DataRequest struct {
	Data interface{} `json:"data"`
}

// RoleRequest represents the structure for role management
type RoleRequest struct {
	UserID string `json:"user_id"` // The target user
	Role   string `json:"role"`    // "user", "employee", or "admin"
	Action string `json:"action"`  // "assign" or "withdraw"
}

// User represents a user in the system
type User struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
}

// DataStore is a simple in-memory data store
type DataStore struct {
	users      map[string]User
	normalData map[string]interface{}
	secretData map[string]interface{}
	mu         sync.RWMutex
}

// NewDataStore creates a new data store with default values
func NewDataStore() *DataStore {
	return &DataStore{
		users: make(map[string]User),
		normalData: map[string]interface{}{
			"items": []string{
				"normal item 1",
				"normal item 2",
			},
		},
		secretData: map[string]interface{}{
			"sensitive_items": []string{
				"confidential item 1",
				"confidential item 2",
			},
		},
	}
}

// APIHandlers contains all the handlers for the API and their dependencies
type APIHandlers struct {
	Enforcer  *casbin.Enforcer
	DataStore *DataStore
	APIGroup  string // Represents the API group (e.g., "v1", "v2", "RyanCompany", "AhmadCompany")
}

// NewAPIHandlers creates a new API handlers instance with the given enforcer and group
func NewAPIHandlers(enforcer *casbin.Enforcer, dataStore *DataStore, apiGroup string) *APIHandlers {
	return &APIHandlers{
		Enforcer:  enforcer,
		DataStore: dataStore,
		APIGroup:  apiGroup,
	}
}

// CreateUser creates a new user with multiple roles
func (h *APIHandlers) CreateUser() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse user creation request
		var userRequest UserRequest
		if err := c.BodyParser(&userRequest); err != nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid request body",
				Data:    nil,
			})
		}

		// Validate input
		if userRequest.UserID == "" || userRequest.Name == "" || len(userRequest.Roles) == 0 {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing required fields",
				Data:    nil,
			})
		}

		// Validate roles
		validRoles := map[string]bool{
			"user":     true,
			"employee": true,
			"admin":    true,
		}

		for _, role := range userRequest.Roles {
			if !validRoles[role] {
				return c.Status(400).JSON(DefaultResponse{
					Status:  "error",
					Message: "Invalid role. Must be 'user', 'employee', or 'admin'",
					Data:    nil,
				})
			}
		}

		// Store user in data store (without roles - roles only in Casbin)
		h.DataStore.mu.Lock()
		h.DataStore.users[userRequest.UserID] = User{
			UserID: userRequest.UserID,
			Name:   userRequest.Name,
		}
		h.DataStore.mu.Unlock()

		// Remove any existing roles first to ensure clean state
		_, err := h.Enforcer.RemoveFilteredGroupingPolicy(0, userRequest.UserID)
		if err != nil {
			// If Casbin fails, remove user from data store
			h.DataStore.mu.Lock()
			delete(h.DataStore.users, userRequest.UserID)
			h.DataStore.mu.Unlock()

			return c.Status(500).JSON(DefaultResponse{
				Status:  "error",
				Message: "Failed to clear existing roles: " + err.Error(),
				Data:    nil,
			})
		}

		// Add all requested roles
		for _, role := range userRequest.Roles {
			fullRole := h.APIGroup + "." + role
			_, err := h.Enforcer.AddGroupingPolicy(userRequest.UserID, fullRole)
			if err != nil {
				// If Casbin fails, remove user from data store
				h.DataStore.mu.Lock()
				delete(h.DataStore.users, userRequest.UserID)
				h.DataStore.mu.Unlock()

				return c.Status(500).JSON(DefaultResponse{
					Status:  "error",
					Message: "Failed to assign role: " + err.Error(),
					Data:    nil,
				})
			}
		}

		return c.Status(201).JSON(DefaultResponse{
			Status:  "success",
			Message: "User created successfully",
			Data:    userRequest.UserID,
		})
	}
}

// ManageRoles handles admin operations to assign or withdraw roles
func (h *APIHandlers) ManageRoles() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get admin ID from locals (set by middleware from header)
		//adminID := c.Locals("adminID").(string)

		// Parse role management request
		var roleRequest RoleRequest
		if err := c.BodyParser(&roleRequest); err != nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid request body",
				Data:    nil,
			})
		}

		// Validate input
		if roleRequest.UserID == "" || roleRequest.Role == "" || roleRequest.Action == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing required fields",
				Data:    nil,
			})
		}

		// Validate role
		validRoles := map[string]bool{
			"user":     true,
			"employee": true,
			"admin":    true,
		}

		if !validRoles[roleRequest.Role] {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid role. Must be 'user', 'employee', or 'admin'",
				Data:    nil,
			})
		}

		// Validate action
		validActions := map[string]bool{
			"assign":   true,
			"withdraw": true,
		}

		if !validActions[roleRequest.Action] {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid action. Must be 'assign' or 'withdraw'",
				Data:    nil,
			})
		}

		// Check if the user exists
		h.DataStore.mu.RLock()
		_, userExists := h.DataStore.users[roleRequest.UserID]
		h.DataStore.mu.RUnlock()

		if !userExists {
			return c.Status(404).JSON(DefaultResponse{
				Status:  "error",
				Message: "User not found",
				Data:    nil,
			})
		}

		// Construct the full role name with the API group
		fullRole := h.APIGroup + "." + roleRequest.Role

		var success bool
		var err error

		if roleRequest.Action == "assign" {
			// Add the role
			success, err = h.Enforcer.AddGroupingPolicy(roleRequest.UserID, fullRole)
		} else {
			// Remove the role
			success, err = h.Enforcer.RemoveGroupingPolicy(roleRequest.UserID, fullRole)
		}

		if err != nil {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "error",
				Message: "Failed to " + roleRequest.Action + " role: " + err.Error(),
				Data:    nil,
			})
		}

		if !success {
			// This could mean the role was already assigned or not assigned
			statusMsg := "Role was already "
			if roleRequest.Action == "assign" {
				statusMsg += "assigned"
			} else {
				statusMsg += "not assigned"
			}

			return c.Status(200).JSON(DefaultResponse{
				Status:  "warning",
				Message: statusMsg,
				Data:    nil,
			})
		}

		// Save the policy to persist changes
		err = h.Enforcer.SavePolicy()
		if err != nil {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "error",
				Message: "Failed to save policy: " + err.Error(),
				Data:    nil,
			})
		}

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Role " + roleRequest.Action + "ed successfully",
			Data:    nil,
		})
	}
}

// GetUsers returns all users or a specific user
func (h *APIHandlers) GetUsers() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get admin ID from locals (set by middleware from header)
		_ = c.Locals("adminID").(string) // We don't need to use it, but it confirms admin access

		userId := c.Params("userId")
		if userId != "" {
			// Return specific user
			h.DataStore.mu.RLock()
			user, exists := h.DataStore.users[userId]
			h.DataStore.mu.RUnlock()

			if !exists {
				return c.Status(404).JSON(DefaultResponse{
					Status:  "error",
					Message: "User not found",
					Data:    nil,
				})
			}

			// Get roles for this user
			roles, err := h.Enforcer.GetRolesForUser(userId)
			if err != nil {
				return c.Status(500).JSON(DefaultResponse{
					Status:  "error",
					Message: "Failed to retrieve roles: " + err.Error(),
					Data:    nil,
				})
			}

			// Prepare response with user details and roles
			response := struct {
				User  User     `json:"user"`
				Roles []string `json:"roles"`
			}{
				User:  user,
				Roles: roles,
			}

			return c.Status(200).JSON(DefaultResponse{
				Status:  "success",
				Message: "User retrieved successfully",
				Data:    response,
			})
		}

		// Return all users
		h.DataStore.mu.RLock()
		users := make([]User, 0, len(h.DataStore.users))
		for _, user := range h.DataStore.users {
			users = append(users, user)
		}
		h.DataStore.mu.RUnlock()

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Users retrieved successfully",
			Data:    users,
		})
	}
}

// ReadNormalData returns normal data for users with appropriate roles
func (h *APIHandlers) ReadNormalData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// User ID already verified by middleware and stored in locals
		_ = c.Locals("userID").(string) // We don't need to use it for reading normal data

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Normal data retrieved successfully",
			Data:    h.DataStore.normalData,
		})
	}
}

// WriteNormalData updates normal data for users with appropriate roles
func (h *APIHandlers) WriteNormalData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// User ID already verified by middleware and stored in locals
		userID := c.Locals("userID").(string) // We don't need to use it for writing normal data

		// Parse data write request
		var dataRequest DataRequest
		if err := c.BodyParser(&dataRequest); err != nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid request body",
				Data:    nil,
			})
		}

		// Validate input
		if dataRequest.Data == nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing data field",
				Data:    nil,
			})
		}

		// Update the normal data
		h.DataStore.mu.Lock()
		h.DataStore.normalData[userID] = dataRequest.Data
		h.DataStore.mu.Unlock()

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Normal data updated successfully",
			Data:    nil,
		})
	}
}

// ReadSecretData returns secret data for users with appropriate roles
func (h *APIHandlers) ReadSecretData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// User ID already verified by middleware and stored in locals
		_ = c.Locals("userID").(string) // We don't need to use it for reading secret data

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Secret data retrieved successfully",
			Data:    h.DataStore.secretData,
		})
	}
}

// WriteSecretData updates secret data for users with appropriate roles
func (h *APIHandlers) WriteSecretData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// User ID already verified by middleware and stored in locals
		adminID := c.Locals("adminID").(string)

		// Parse data write request
		var dataRequest DataRequest
		if err := c.BodyParser(&dataRequest); err != nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid request body",
				Data:    nil,
			})
		}

		// Validate input
		if dataRequest.Data == nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing data field",
				Data:    nil,
			})
		}

		// Update the secret data
		h.DataStore.mu.Lock()
		h.DataStore.secretData[adminID] = dataRequest.Data
		h.DataStore.mu.Unlock()

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Secret data updated successfully",
			Data:    nil,
		})
	}
}
