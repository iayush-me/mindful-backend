package models

import (
    "context"
    "github.com/jackc/pgx/v5/pgxpool"
    "log"
    "os"

    "database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ScheduledTask struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Date        time.Time
	TaskID      string
	Time        string  // Expected format "HH:mm"
	Task        string
	Done        bool
	MoodCaption string
	Sentiment   *float64 // Nullable float64 for sentiment score
}
func InsertScheduledTask(ctx context.Context, task ScheduledTask) error {
	_, err := DB.Exec(ctx,
		`INSERT INTO scheduled_tasks 
		(id, user_id, date, task_id, time, task, done, mood_caption, sentiment) 
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		task.ID, task.UserID, task.Date, task.TaskID, task.Time, task.Task, task.Done, task.MoodCaption, task.Sentiment)
	return err
}
func FetchScheduledTasksByDate(ctx context.Context, userID uuid.UUID, date time.Time) ([]ScheduledTask, error) {
	rows, err := DB.Query(ctx,
		`SELECT id, task_id, time, task, done, mood_caption, sentiment
		FROM scheduled_tasks 
		WHERE user_id=$1 AND date=$2 
		ORDER BY time ASC`,
		userID, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []ScheduledTask
	for rows.Next() {
		var t ScheduledTask
		t.UserID = userID
		t.Date = date

		var sentiment sql.NullFloat64
		var moodCaption sql.NullString

		if err = rows.Scan(&t.ID, &t.TaskID, &t.Time, &t.Task, &t.Done, &moodCaption, &sentiment); err != nil {
			return nil, err
		}

		if moodCaption.Valid {
			t.MoodCaption = moodCaption.String
		}
		if sentiment.Valid {
			val := sentiment.Float64
			t.Sentiment = &val
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// UpdateScheduledTask updates task fields such as done status, description, or time
func UpdateScheduledTask(ctx context.Context, userID uuid.UUID, taskID string, done *bool, taskDesc *string, timeStr *string) error {
	setParts := []string{}
	params := []interface{}{}
	idx := 1

	if done != nil {
		setParts = append(setParts, fmt.Sprintf("done = $%d", idx))
		params = append(params, *done)
		idx++
	}
	if taskDesc != nil {
		setParts = append(setParts, fmt.Sprintf("task = $%d", idx))
		params = append(params, *taskDesc)
		idx++
	}
	if timeStr != nil {
		setParts = append(setParts, fmt.Sprintf("time = $%d", idx))
		params = append(params, *timeStr)
		idx++
	}
	if len(setParts) == 0 {
		return errors.New("no updates provided")
	}

	sqlStr := fmt.Sprintf("UPDATE scheduled_tasks SET %s WHERE user_id = $%d AND task_id = $%d",
		strings.Join(setParts, ", "), idx, idx+1)
	params = append(params, userID, taskID)

	_, err := DB.Exec(ctx, sqlStr, params...)
	return err
}

// UpdateTaskMood updates mood caption text and sentiment score for a given task
func UpdateTaskMood(ctx context.Context, userID uuid.UUID, taskID, moodCaption string, sentiment float64) error {
	_, err := DB.Exec(ctx,
		`UPDATE scheduled_tasks 
		SET mood_caption=$1, sentiment=$2 
		WHERE user_id=$3 AND task_id=$4`,
		moodCaption, sentiment, userID, taskID)
	return err
}
var DB *pgxpool.Pool

func ConnectDB() {
    dsn := os.Getenv("DATABASE_URL") // e.g. "postgres://user:pass@localhost:5432/dbname"
    var err error
    DB, err = pgxpool.New(context.Background(), dsn)
    if err != nil {
        log.Fatal("Unable to connect to database:", err)
    }
    // Optional: set max connections, idle timeout, etc.
}
