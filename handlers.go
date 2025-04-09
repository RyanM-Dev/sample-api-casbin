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

// DataRequest includes only user ID in all data operations
type DataRequest struct {
	UserID string      `json:"user_id"`
	Data   interface{} `json:"data"`
}

// RoleRequest represents the structure for role management
// RoleRequest represents the structure for role management
type RoleRequest struct {
	AdminID string `json:"admin_id"`
	UserID  string `json:"user_id"` // The target user
	Role    string `json:"role"`    // "user", "employee", or "admin"
	Action  string `json:"action"`  // "assign" or "withdraw"
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

		// Add all roles to the user in Casbin
		for _, role := range userRequest.Roles {
			_, err := h.Enforcer.AddGroupingPolicy(userRequest.UserID, h.APIGroup+"."+role)
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

		// Save policy
		err = h.Enforcer.SavePolicy()
		if err != nil {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "error",
				Message: "Failed to save policy: " + err.Error(),
				Data:    nil,
			})
		}

		return c.JSON(DefaultResponse{
			Status:  "success",
			Message: "User created successfully",
			Data: map[string]interface{}{
				"user_id":   userRequest.UserID,
				"name":      userRequest.Name,
				"roles":     userRequest.Roles,
				"api_group": h.APIGroup,
			},
		})
	}
}

// ReadNormalData handles read operations for normal data
func (h *APIHandlers) ReadNormalData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// userID is now in query params instead of from path params
		userID := c.Query("userId")
		if userID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "User ID is required in query parameters",
				Data:    nil,
			})
		}

		// Check if user exists
		h.DataStore.mu.RLock()
		_, exists := h.DataStore.users[userID]
		h.DataStore.mu.RUnlock()

		if !exists {
			return c.Status(404).JSON(DefaultResponse{
				Status:  "error",
				Message: "User not found",
				Data:    nil,
			})
		}

		// Return normal data
		h.DataStore.mu.RLock()
		data := h.DataStore.normalData
		h.DataStore.mu.RUnlock()

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Normal data retrieved successfully",
			Data:    data,
		})
	}
}

// WriteNormalData handles write operations for normal data
func (h *APIHandlers) WriteNormalData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse incoming data with userID
		var request DataRequest
		if err := c.BodyParser(&request); err != nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid request body",
				Data:    nil,
			})
		}

		// Validate userID
		if request.UserID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing user_id in request",
				Data:    nil,
			})
		}

		// Store userID in context for middleware use
		c.Locals("userID", request.UserID)

		// Store the data
		h.DataStore.mu.Lock()
		h.DataStore.normalData[request.UserID] = request.Data
		h.DataStore.mu.Unlock()

		return c.JSON(DefaultResponse{
			Status:  "success",
			Message: "Data written successfully",
			Data: map[string]interface{}{
				"api_group": h.APIGroup,
				"data":      request.Data,
			},
		})
	}
}

// ReadSecretData handles read operations for secret/important data

func (h *APIHandlers) ReadSecretData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// userID is now in query params instead of from path params
		userID := c.Query("userId")
		if userID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "User ID is required in query parameters",
				Data:    nil,
			})
		}

		// Check if user exists
		h.DataStore.mu.RLock()
		_, exists := h.DataStore.users[userID]
		h.DataStore.mu.RUnlock()

		if !exists {
			return c.Status(404).JSON(DefaultResponse{
				Status:  "error",
				Message: "User not found",
				Data:    nil,
			})
		}

		// Return secret data
		h.DataStore.mu.RLock()
		data := h.DataStore.secretData
		h.DataStore.mu.RUnlock()

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Secret data retrieved successfully",
			Data:    data,
		})
	}
}

// WriteSecretData handles write operations for secret/important data
func (h *APIHandlers) WriteSecretData() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse incoming data with userID
		var request DataRequest
		if err := c.BodyParser(&request); err != nil {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid request body",
				Data:    nil,
			})
		}

		// Validate userID
		if request.UserID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Missing user_id in request",
				Data:    nil,
			})
		}

		// Store userID in context for middleware use
		c.Locals("userID", request.UserID)

		// Store the data
		h.DataStore.mu.Lock()
		h.DataStore.secretData[request.UserID] = request.Data
		h.DataStore.mu.Unlock()

		return c.JSON(DefaultResponse{
			Status:  "success",
			Message: "Secret data written successfully",
			Data: map[string]interface{}{
				"api_group": h.APIGroup,
				"data":      request.Data,
			},
		})
	}
}

// ManageRoles manages role assignments and withdrawals using Casbin
// ManageRole assigns or withdraws roles from users, accessible only to admins
func (h *APIHandlers) ManageRoles() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get admin ID from query parameters

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

		//Check if admin exists
		h.DataStore.mu.RLock()
		_, adminExists := h.DataStore.users[roleRequest.AdminID]
		h.DataStore.mu.RUnlock()

		if !adminExists {
			return c.Status(404).JSON(DefaultResponse{
				Status:  "error",
				Message: "Admin not found",
				Data:    nil,
			})
		}

		//Check if target user exists
		h.DataStore.mu.RLock()
		_, userExists := h.DataStore.users[roleRequest.UserID]
		h.DataStore.mu.RUnlock()

		if !userExists {
			return c.Status(404).JSON(DefaultResponse{
				Status:  "error",
				Message: "Target user not found",
				Data:    nil,
			})
		}

		//Validate role
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
		if roleRequest.Action != "assign" && roleRequest.Action != "withdraw" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "Invalid action. Must be 'assign' or 'withdraw'",
				Data:    nil,
			})
		}

		var success bool
		var err error

		// Assign or withdraw role
		if roleRequest.Action == "assign" {
			// Check if the user already has this role
			roles, err := h.Enforcer.GetRolesForUser(roleRequest.UserID)
			if err != nil {
				return c.Status(500).JSON(DefaultResponse{
					Status:  "error",
					Message: "Failed to get roles: " + err.Error(),
					Data:    nil,
				})
			}

			hasRole := false
			for _, r := range roles {
				if r == roleRequest.Role {
					hasRole = true
					break
				}
			}

			if hasRole {
				return c.Status(400).JSON(DefaultResponse{
					Status:  "error",
					Message: "User already has this role",
					Data:    nil,
				})
			}

			// Add role for the user
			success, err = h.Enforcer.AddRoleForUser(roleRequest.UserID, roleRequest.Role)
		} else {
			// Remove role for the user
			success, err = h.Enforcer.DeleteRoleForUser(roleRequest.UserID, roleRequest.Role)
		}

		if err != nil {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "error",
				Message: "Failed to " + roleRequest.Action + " role: " + err.Error(),
				Data:    nil,
			})
		}

		if !success {
			return c.Status(500).JSON(DefaultResponse{
				Status:  "error",
				Message: "Failed to " + roleRequest.Action + " role",
				Data:    nil,
			})
		}

		// Save Casbin policy
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

// GetUsers returns all users with their roles from Casbin
// GetUsers retrieves all users
func (h *APIHandlers) GetUsers() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// userID is now in query params instead of from path params
		userID := c.Query("userId")
		if userID == "" {
			return c.Status(400).JSON(DefaultResponse{
				Status:  "error",
				Message: "User ID is required in query parameters",
				Data:    nil,
			})
		}

		// Check if user exists
		h.DataStore.mu.RLock()
		_, exists := h.DataStore.users[userID]
		h.DataStore.mu.RUnlock()

		if !exists {
			return c.Status(404).JSON(DefaultResponse{
				Status:  "error",
				Message: "User not found",
				Data:    nil,
			})
		}

		// Return all users
		h.DataStore.mu.RLock()
		userList := make([]User, 0, len(h.DataStore.users))
		for _, user := range h.DataStore.users {
			userList = append(userList, user)
		}
		h.DataStore.mu.RUnlock()

		return c.Status(200).JSON(DefaultResponse{
			Status:  "success",
			Message: "Users retrieved successfully",
			Data:    userList,
		})
	}
}
