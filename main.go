package main

import (
    "os"
    "github.com/gin-contrib/cors"
	"time"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "log"
    "mindful-moments/internal/api"
    "mindful-moments/internal/models"
)

func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        frontendOrigin := os.Getenv("FRONTEND_URL")
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

    // Connect to PostgreSQL database (the function exits if it fails)
    models.ConnectDB()

    // Create Gin router
    r := gin.Default()

    // Enable CORS (so React and other frontends can access your API)
    //r.Use(cors.Default())
    frontendOrigin := os.Getenv("FRONTEND_URL")
	r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{frontendOrigin}, // your frontend URL
    AllowMethods:     []string{"GET", "POST","PATCH","PUT","DELETE", "OPTIONS"},
    AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
    ExposeHeaders:    []string{"Content-Length"},
    AllowCredentials: true,
    MaxAge: 12 * time.Hour,
}))

    // Register API routes
    api.SetupRoutes(r)
    r.Static("/static", "./avatars")

    // Start server on port 8080
    if err := r.Run(":8080"); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
