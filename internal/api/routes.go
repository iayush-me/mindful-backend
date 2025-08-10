package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mindful-moments/internal/models"
	"net/http"
	"path/filepath"
	"strings"
	"time"
    "regexp"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"crypto/rand"
	"encoding/hex"
	"net/smtp"
)
var smtpHost = "smtp.gmail.com"                // SMTP server host, adjust for provider
var smtpPort = 587                             // Port for TLS (587 for STARTTLS)
var smtpUser = "your@gmail.com"                // SMTP login
var smtpPass = "your_app_password_here"        // Use app password or real SMTP user password
var fromEmail = "Mindful Moments <your@gmail.com>" // Shown as sender
var timeRegexp = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)




    
    
    



var jwtSecret = []byte("my_secret_key") // For demo only, use ENV for production

// -------- JWT Authentication Middleware --------
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        userID, err := getUserIDFromToken(c)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            c.Abort()
            return
        }
        c.Set("userID", userID)
        c.Next()
    }
}

func getUserIDFromContext(c *gin.Context) (string, error) {
    v, exists := c.Get("userID")
    if !exists {
        return "", errors.New("userID not found in context")
    }
    userID, ok := v.(string)
    if !ok {
        return "", errors.New("userID invalid type")
    }
    return userID, nil
}

func getUserIDFromToken(c *gin.Context) (string, error) {
    h := c.GetHeader("Authorization")
    if h == "" || !strings.HasPrefix(h, "Bearer ") {
        return "", errors.New("no token")
    }
    tokenStr := strings.TrimPrefix(h, "Bearer ")
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })
    if err != nil || !token.Valid {
        return "", errors.New("invalid token")
    }
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return "", errors.New("user_id not found")
    }
    userID, ok := claims["user_id"].(string)
    if !ok {
        return "", errors.New("user_id not found")
    }
    return userID, nil
}

// -------- Setup Routes --------
func SetupRoutes(r *gin.Engine) {
    r.POST("/register", Register)
    r.POST("/login", Login)
    r.POST("/forgot-password", ForgotPassword)
    r.POST("/reset-password", ResetPassword)

    authGroup := r.Group("/", AuthMiddleware())
    authGroup.GET("/schedule", GetSchedule)
    authGroup.POST("/schedule", SetSchedule)
    authGroup.PATCH("/user/reminder", UpdateReminderSettings)
    authGroup.POST("/mood", PostMood)
    authGroup.GET("/mood-history", GetMoodHistory)
    authGroup.GET("/stats", GetStats)
    authGroup.GET("/user/profile", GetUserProfile)
    authGroup.PATCH("/user/profile", UpdateUserProfile)
    authGroup.POST("/user/password", ChangePassword)
    authGroup.POST("/user/avatar", UploadAvatar)
    authGroup.GET("/schedule/today", GetScheduleToday)
    authGroup.POST("/schedule/add", AddTask)
    authGroup.POST("/schedule/update", UpdateTask)
    authGroup.POST("/schedule/mood", SaveTaskMood)
    authGroup.GET("/schedule/daily-mood-summary", GetDailyMoodSummary)



    

}

// -------- Registration --------
func Register(c *gin.Context) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
        return
    }
    id := uuid.New()
    _, err = models.DB.Exec(context.Background(),
        "INSERT INTO users (id, email, password) VALUES ($1, $2, $3)",
        id, req.Email, string(hashed),
    )
    if err != nil {
        fmt.Println("Registration error:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Email already used or DB error"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

// -------- Login --------
func Login(c *gin.Context) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    row := models.DB.QueryRow(context.Background(), "SELECT id, password FROM users WHERE email=$1", req.Email)
    var userID string
    var hashed string
    if err := row.Scan(&userID, &hashed); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(req.Password)) != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "email":   req.Email,
    })
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// -------- Schedule Endpoints --------
func GetSchedule(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    row := models.DB.QueryRow(context.Background(), "SELECT break_time FROM schedules WHERE user_id=$1", userID)
    var breaks []string
    if err := row.Scan(&breaks); err != nil {
        c.JSON(http.StatusOK, gin.H{"break_time": []string{}})
        return
    }
    c.JSON(http.StatusOK, gin.H{"break_time": breaks})
}

func SetSchedule(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    var req struct {
        BreakTime []string `json:"break_time"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }
    _, err = models.DB.Exec(context.Background(),
        `INSERT INTO schedules (user_id, break_time) VALUES ($1, $2)
        ON CONFLICT (user_id) DO UPDATE SET break_time = $2`,
        userID, req.BreakTime,
    )
    if err != nil {
        fmt.Println("DB error in SetSchedule:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Schedule saved"})
}
//reminder
func UpdateReminderSettings(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    var r struct {
        ReminderEnabled bool   `json:"reminderEnabled"`
        ReminderTime    string `json:"reminderTime"` // expect "HH:mm" format
    }
    if err := c.ShouldBindJSON(&r); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    var reminderTimeNull interface{} = nil
    if r.ReminderEnabled {
        t, err := time.Parse("15:04", r.ReminderTime)
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid time format"})
            return
        }
        reminderTimeNull = t.Format("15:04:00") // Store as time string for SQL TIME column
    }

    _, err = models.DB.Exec(context.Background(),
        `UPDATE users SET reminder_enabled=$1, reminder_time=$2 WHERE id=$3`,
        r.ReminderEnabled, reminderTimeNull, userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Reminder settings updated"})
}

// -------- Mood Endpoints --------
func PostMood(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    var req struct {
        Message string `json:"message"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    sentiment := 0.0 // fallback if AI service fails
    aiReq, _ := json.Marshal(map[string]string{"message": req.Message})
    httpResp, err := http.Post("http://localhost:9000/analyze", "application/json", bytes.NewBuffer(aiReq))
    if err != nil {
        fmt.Println("Could not reach AI service:", err)
    } else if httpResp.StatusCode == 200 {
        var aiResp struct {
            Sentiment float64 `json:"sentiment"`
        }
        json.NewDecoder(httpResp.Body).Decode(&aiResp)
        sentiment = aiResp.Sentiment
        httpResp.Body.Close()
    } else {
        fmt.Println("AI service returned HTTP", httpResp.StatusCode)
    }

    moodID := uuid.New()
    _, err = models.DB.Exec(context.Background(),
        "INSERT INTO moods (id, user_id, message, sentiment) VALUES ($1, $2, $3, $4)",
        moodID, userID, req.Message, sentiment,
    )
    if err != nil {
        fmt.Println("DB error in PostMood:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    c.JSON(http.StatusOK, gin.H{
        "message":   "Mood saved",
        "sentiment": sentiment,
    })
}

// Handler: returns all moods for logged-in user in ascending date order (for charts)
func GetMoodHistory(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    rows, err := models.DB.Query(context.Background(),
        "SELECT timestamp, sentiment, message FROM moods WHERE user_id=$1 ORDER BY timestamp ASC", userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    defer rows.Close()

    moods := []map[string]interface{}{}
    for rows.Next() {
        var ts time.Time
        var sent float64
        var msg string
        if err := rows.Scan(&ts, &sent, &msg); err != nil {
            fmt.Println("Error scanning mood row:", err)
            continue
        }
        moods = append(moods, map[string]interface{}{
            "timestamp": ts.Format("2006-01-02"),
            "sentiment": sent,
            "message":   msg,
        })
    }
    c.JSON(http.StatusOK, gin.H{"moods": moods})
}


func GetStats(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    rows, err := models.DB.Query(context.Background(),
        "SELECT timestamp, message, sentiment FROM moods WHERE user_id=$1 ORDER BY timestamp DESC LIMIT 10", userID)
    if err != nil {
        fmt.Println("Error querying moods:", err) // Add if missing
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    defer rows.Close()

    stats := []map[string]interface{}{}
    for rows.Next() {
        var ts time.Time
        var msg string
        var sent float64
        err := rows.Scan(&ts, &msg, &sent)
        if err != nil {
            fmt.Println("Error scanning mood row:", err)
            continue
        }
        stats = append(stats, map[string]interface{}{
            "timestamp": ts.Format("2006-01-02 15:04:05"),
            "message":   msg,
            "sentiment": sent,
        })
    }

    c.JSON(http.StatusOK, gin.H{"moods": stats})
}

// -------- User Profile Endpoints --------


func GetUserProfile(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    row := models.DB.QueryRow(
        context.Background(),
        "SELECT email, display_name, birthday, notifications, avatar_url FROM users WHERE id=$1",
        userID,
    )
    var (
        email        string
        displayName  sql.NullString
        birthday     *time.Time
        notifications bool
        avatarURL    sql.NullString
    )

    err = row.Scan(&email, &displayName, &birthday, &notifications, &avatarURL)
    if err != nil {
        fmt.Println("Error in GetUserProfile/Scan:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "email": email,
        "displayName": func() *string {
            if displayName.Valid {
                return &displayName.String
            }
            return nil
        }(),
        "birthday": func() *string {
            if birthday != nil {
                str := birthday.Format("2006-01-02")
                return &str
            }
            return nil
        }(),
        "notifications": notifications,
        "avatarUrl": func() *string {
            if avatarURL.Valid {
                return &avatarURL.String
            }
            return nil
        }(),
    })
}


func UpdateUserProfile(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    var req struct {
        Email         *string `json:"email"`
        DisplayName   *string `json:"displayName"`
        Birthday      *string `json:"birthday"`
        Notifications *bool   `json:"notifications"`
        AvatarUrl     *string `json:"avatarUrl"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    updates := []string{}
    args := []interface{}{}
    argIdx := 1

    if req.Email != nil {
        updates = append(updates, fmt.Sprintf("email = $%d", argIdx))
        args = append(args, *req.Email)
        argIdx++
    }
    if req.DisplayName != nil {
        updates = append(updates, fmt.Sprintf("display_name = $%d", argIdx))
        args = append(args, *req.DisplayName)
        argIdx++
    }
    if req.Birthday != nil {
        if *req.Birthday == "" {
            updates = append(updates, fmt.Sprintf("birthday = $%d", argIdx))
            args = append(args, nil)
            argIdx++
        } else {
            bday, err := time.Parse("2006-01-02", *req.Birthday)
            if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": "Birthday format must be YYYY-MM-DD"})
                return
            }
            updates = append(updates, fmt.Sprintf("birthday = $%d", argIdx))
            args = append(args, bday)
            argIdx++
        }
    }
    if req.Notifications != nil {
        updates = append(updates, fmt.Sprintf("notifications = $%d", argIdx))
        args = append(args, *req.Notifications)
        argIdx++
    }
    if req.AvatarUrl != nil {
        updates = append(updates, fmt.Sprintf("avatar_url = $%d", argIdx))
        args = append(args, *req.AvatarUrl)
        argIdx++
    }

    if len(updates) == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Nothing to update"})
        return
    }

    args = append(args, userID)
    sqlStr := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(updates, ", "), argIdx)
    _, err = models.DB.Exec(context.Background(), sqlStr, args...)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Profile updated"})
}

// POST /user/password
func ChangePassword(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    var req struct{ Password string `json:"password"` }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }
    if len(req.Password) < 6 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters"})
        return
    }

    hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
        return
    }
    _, err = models.DB.Exec(context.Background(),
        "UPDATE users SET password=$1 WHERE id=$2", string(hashed), userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error updating password"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// POST /user/avatar
func UploadAvatar(c *gin.Context) {
    userID, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    file, err := c.FormFile("avatar")
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
        return
    }
    filename := fmt.Sprintf("avatars/%s_%s", userID, filepath.Base(file.Filename))
    if err := c.SaveUploadedFile(file, filename); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Upload failed"})
        return
    }
    avatarURL := "/static/" + filename

    _, err = models.DB.Exec(context.Background(),
        "UPDATE users SET avatar_url=$1 WHERE id=$2", avatarURL, userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"avatarUrl": avatarURL})
}


//reset password-------------------------
func sendResetEmailViaSMTP(toEmail, resetURL string) error {
    subject := "Reset your password"
    body := fmt.Sprintf(
        `Hi,

We received a request to reset your Mindful Moments password.

Click the link below or copy it into your browser to reset your password:
%s

If you did not request a password reset, you can safely ignore this email.

– The Mindful Moments Team
`, resetURL)
    msg := "From: " + fromEmail + "\r\n" +
        "To: " + toEmail + "\r\n" +
        "Subject: " + subject + "\r\n" +
        "MIME-Version: 1.0\r\n" +
        "Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body

    addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
    auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
    return smtp.SendMail(addr, auth, smtpUser, []string{toEmail}, []byte(msg))
}
//forgot password
func generateToken() (string, error) {
    b := make([]byte, 24)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

func ForgotPassword(c *gin.Context) {
    var req struct { Email string `json:"email"` }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    // Always respond generically (no user enumeration)
    genericMsg := gin.H{"message": "If an account exists for this email, reset instructions were sent."}

    // Find user ID by email
    var userID string
    err := models.DB.QueryRow(context.Background(), "SELECT id FROM users WHERE email=$1", req.Email).Scan(&userID)
    if err != nil {
        // Always respond with same message (don't reveal if email exists or not)
        c.JSON(http.StatusOK, genericMsg)
        return
    }

    // Generate secure token
    tokenBytes := make([]byte, 24)
    _, err = rand.Read(tokenBytes)
    if err != nil {
        // Log actual error for debugging (not for user)
        fmt.Println("Error generating reset token:", err)
        c.JSON(http.StatusInternalServerError, genericMsg)
        return
    }
    token := hex.EncodeToString(tokenBytes)
    expiresAt := time.Now().Add(1 * time.Hour)

    // Store reset token
    _, err = models.DB.Exec(context.Background(),
        `INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)`, userID, token, expiresAt,
    )
    if err != nil {
        fmt.Println("DB error storing reset token:", err)
        c.JSON(http.StatusOK, genericMsg) // Do not reveal more
        return
    }

    // Prepare the reset URL – your deployed frontend domain or localhost for dev
    resetURL := fmt.Sprintf("https://your-frontend.com/reset-password?token=%s", token) // Change domain in prod

    // Send the email via SMTP – for dev, log error to server console
    if err := sendResetEmailViaSMTP(req.Email, resetURL); err != nil {
        fmt.Println("Failed to send reset email:", err)
        // Still reply with same generic message for security
    }

    c.JSON(http.StatusOK, genericMsg)
}

func ResetPassword(c *gin.Context) {
    var req struct {
        Token    string `json:"token"`
        Password string `json:"password"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    if len(req.Password) < 6 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters"})
        return
    }

    var userID string
    var expiresAt time.Time
    var used bool

    err := models.DB.QueryRow(context.Background(),
        "SELECT user_id, expires_at, used FROM password_resets WHERE token=$1", req.Token).
        Scan(&userID, &expiresAt, &used)

    if err != nil || used || time.Now().After(expiresAt) {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token"})
        return
    }

    hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println("Error hashing password:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password reset"})
        return
    }

    tx, err := models.DB.Begin(context.Background())
    if err != nil {
        fmt.Println("Error starting transaction:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password reset"})
        return
    }

    // Attempt to update user password
    _, err = tx.Exec(context.Background(), "UPDATE users SET password=$1 WHERE id=$2", string(hashedPwd), userID)
    if err != nil {
        tx.Rollback(context.Background())
        fmt.Println("Error updating password:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
        return
    }

    // Mark token as used
    _, err = tx.Exec(context.Background(), "UPDATE password_resets SET used=true WHERE token=$1", req.Token)
    if err != nil {
        tx.Rollback(context.Background())
        fmt.Println("Error updating token usage:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to finalize password reset"})
        return
    }

    err = tx.Commit(context.Background())
    if err != nil {
        fmt.Println("Error committing transaction:", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete password reset"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

// GET /schedule/today
func GetScheduleToday(c *gin.Context) {
    userIDStr, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
        return
    }

    today := time.Now().Truncate(24 * time.Hour)
    tasks, err := models.FetchScheduledTasksByDate(c.Request.Context(), userID, today)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching scheduled tasks"})
        return
    }

    respTasks := []gin.H{}
    for _, t := range tasks {
        var sent interface{} = nil
        if t.Sentiment != nil {
            sent = *t.Sentiment
        }
        respTasks = append(respTasks, gin.H{
            "id":          t.ID.String(),
            "taskId":      t.TaskID,
            "time":        t.Time,
            "task":        t.Task,
            "done":        t.Done,
            "moodCaption": t.MoodCaption,
            "sentiment":   sent,
        })
    }
    c.JSON(http.StatusOK, gin.H{"tasks": respTasks})
}

// POST /schedule/add
func AddTask(c *gin.Context) {
    userIDStr, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
        return
    }

    var req struct {
        TaskID string `json:"taskId"`
        Time   string `json:"time"` // HH:mm
        Task   string `json:"task"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }
    if !timeRegexp.MatchString(req.Time) {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid time format"})
        return
    }

    t := models.ScheduledTask{
        ID:          uuid.New(),
        UserID:      userID,
        Date:        time.Now().Truncate(24 * time.Hour),
        TaskID:      req.TaskID,
        Time:        req.Time,
        Task:        req.Task,
        Done:        false,
        MoodCaption: "",
        Sentiment:   nil,
    }

    if err := models.InsertScheduledTask(c.Request.Context(), t); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error inserting task"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Task added"})
}

// POST /schedule/update
func UpdateTask(c *gin.Context) {
    userIDStr, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
        return
    }

    var req struct {
        TaskID string  `json:"taskId"`
        Done   *bool   `json:"done,omitempty"`
        Task   *string `json:"task,omitempty"`
        Time   *string `json:"time,omitempty"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }
    if req.Time != nil && !timeRegexp.MatchString(*req.Time) {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid time format"})
        return
    }

    if err := models.UpdateScheduledTask(c.Request.Context(), userID, req.TaskID, req.Done, req.Task, req.Time); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error updating task"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Task updated"})
}

// POST /schedule/mood
func SaveTaskMood(c *gin.Context) {
    userIDStr, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
        return
    }

    var req struct {
        TaskID      string  `json:"taskId"`
        MoodCaption string  `json:"moodCaption"`
        Sentiment   float64 `json:"sentiment"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    if err := models.UpdateTaskMood(c.Request.Context(), userID, req.TaskID, req.MoodCaption, req.Sentiment); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error saving mood"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Mood saved"})
}
// GET /schedule/daily-mood-summary
func GetDailyMoodSummary(c *gin.Context) {
    userIDStr, err := getUserIDFromContext(c)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
        return
    }

    today := time.Now().Truncate(24 * time.Hour)
    rows, err := models.DB.Query(
        c.Request.Context(),
        "SELECT sentiment FROM scheduled_tasks WHERE user_id=$1 AND date=$2 AND sentiment IS NOT NULL",
        userID, today,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
        return
    }
    defer rows.Close()

    var sentiments []float64
    for rows.Next() {
        var s float64
        if err := rows.Scan(&s); err == nil {
            sentiments = append(sentiments, s)
        }
    }

    avg := 0.0
    pos, neg, neutral := 0, 0, 0
    if len(sentiments) > 0 {
        total := 0.0
        for _, s := range sentiments {
            total += s
            switch {
            case s > 0.2:
                pos++
            case s < -0.2:
                neg++
            default:
                neutral++
            }
        }
        avg = total / float64(len(sentiments))
    }

    c.JSON(http.StatusOK, gin.H{
        "dailyMood": gin.H{
            "avgMood":       avg,
            "positiveCount": pos,
            "neutralCount":  neutral,
            "negativeCount": neg,
            "total":         len(sentiments),
        },
    })
}

