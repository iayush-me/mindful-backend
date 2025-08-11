package main

import (
    "fmt"
    "log"
    "os"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"

    "mindful-moments/internal/api"
    "mindful-moments/internal/models"
)

func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        frontendOrigin := os.Getenv("FRONTEND_URL")
        if frontendOrigin == "" {
            frontendOrigin = "http://localhost:3000" // fallback for local dev
        }

        c.Writer.Header().Set("Access-Control-Allow-Origin", frontendOrigin)
        c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Authorization, Content-Type")
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    }
}

func main() {
    // Load environment variables from .env if it exists
    if err := godotenv.Load(); err != nil {
        log.Println(".env file not found, using system environment variables instead.")
    }

    // Connect to PostgreSQL database
    models.ConnectDB()

    // Create Gin router
    r := gin.Default()

    // Enable CORS
    frontendOrigin := os.Getenv("FRONTEND_URL")
    if frontendOrigin == "" {
        frontendOrigin = "http://localhost:3000" // fallback
    }
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{frontendOrigin},
        AllowMethods:     []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }))

    // Register API routes
    api.SetupRoutes(r)
    r.Static("/static", "./avatars")

    // Get port from environment (Render sets PORT at runtime)
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080" // default for local dev
    }

    // Start server
    if err := r.Run(":" + port); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }

    fmt.Printf("Server running on port %s\n", port)
}
