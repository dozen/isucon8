package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
)

type User struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
	Price     int32  `json:"price,omitempty"`
}

type Event struct {
	ID       int64  `json:"id,omitempty"`
	Title    string `json:"title,omitempty"`
	PublicFg bool   `json:"public,omitempty"`
	ClosedFg bool   `json:"closed,omitempty"`
	Price    int64  `json:"price,omitempty"`

	Total   int                `json:"total"`
	Remains int                `json:"remains"`
	Sheets  map[string]*Sheets `json:"sheets,omitempty"`
}

type Sheets struct {
	Total   int      `json:"total"`
	Remains int      `json:"remains"`
	Detail  []*Sheet `json:"detail,omitempty"`
	Price   int64    `json:"price"`
}

type Sheet struct {
	ID    int64  `json:"-"`
	Rank  string `json:"-"`
	Num   int64  `json:"num"`
	Price int64  `json:"-"`

	Mine           bool       `json:"mine,omitempty"`
	Reserved       bool       `json:"reserved,omitempty"`
	ReservedAt     *time.Time `json:"-"`
	ReservedAtUnix int64      `json:"reserved_at,omitempty"`
}

type Reservation struct {
	ID         int64      `json:"id"`
	EventID    int64      `json:"-"`
	SheetID    int64      `json:"-"`
	UserID     int64      `json:"-"`
	ReservedAt *time.Time `json:"-"`
	CanceledAt *time.Time `json:"-"`

	Event          *Event `json:"event,omitempty"`
	SheetRank      string `json:"sheet_rank,omitempty"`
	SheetNum       int64  `json:"sheet_num,omitempty"`
	Price          int64  `json:"price,omitempty"`
	ReservedAtUnix int64  `json:"reserved_at,omitempty"`
	CanceledAtUnix int64  `json:"canceled_at,omitempty"`
}

type Administrator struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
}

func sessUserID(c echo.Context) int64 {
	sess, _ := session.Get("session", c)
	var userID int64
	if x, ok := sess.Values["user_id"]; ok {
		userID, _ = x.(int64)
	}
	return userID
}

func sessSetUserID(c echo.Context, id int64) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	sess.Values["user_id"] = id
	sess.Save(c.Request(), c.Response())
}

func sessDeleteUserID(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	delete(sess.Values, "user_id")
	sess.Save(c.Request(), c.Response())
}

func sessAdministratorID(c echo.Context) int64 {
	sess, _ := session.Get("session", c)
	var administratorID int64
	if x, ok := sess.Values["administrator_id"]; ok {
		administratorID, _ = x.(int64)
	}
	return administratorID
}

func sessSetAdministratorID(c echo.Context, id int64) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	sess.Values["administrator_id"] = id
	sess.Save(c.Request(), c.Response())
}

func sessDeleteAdministratorID(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	delete(sess.Values, "administrator_id")
	sess.Save(c.Request(), c.Response())
}

func loginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, err := getLoginUser(c); err != nil {
			return resError(c, "login_required", 401)
		}
		return next(c)
	}
}

func adminLoginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, err := getLoginAdministrator(c); err != nil {
			return resError(c, "admin_login_required", 401)
		}
		return next(c)
	}
}

func getLoginUser(c echo.Context) (*User, error) {
	userID := sessUserID(c)
	if userID == 0 {
		return nil, errors.New("not logged in")
	}
	var user User
	err := db.QueryRow("SELECT id, nickname FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Nickname)
	return &user, err
}

func getLoginAdministrator(c echo.Context) (*Administrator, error) {
	administratorID := sessAdministratorID(c)
	if administratorID == 0 {
		return nil, errors.New("not logged in")
	}
	var administrator Administrator
	err := db.QueryRow("SELECT id, nickname FROM administrators WHERE id = ?", administratorID).Scan(&administrator.ID, &administrator.Nickname)
	return &administrator, err
}

func getEvents(all bool) ([]*Event, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Commit()

	rows, err := tx.Query("SELECT * FROM events ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	eventIDs := make([]int64, 0, 30)

	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
			return nil, err
		}
		if !all && !event.PublicFg {
			continue
		}
		eventIDs = append(eventIDs, event.ID)
	}

	return getEventsByIDs(eventIDs, -1)
}

func getEvent(eventID, loginUserID int64) (*Event, error) {
	var event Event
	if err := db.QueryRow("SELECT * FROM events WHERE id = ?", eventID).Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
		return nil, err
	}
	event.Sheets = map[string]*Sheets{
		"S": {},
		"A": {},
		"B": {},
		"C": {},
	}
	for _, cSheet := range cachedSheets {
		sheet := *cSheet
		event.Sheets[sheet.Rank].Price = event.Price + sheet.Price
		event.Total++
		event.Sheets[sheet.Rank].Total++
		var reservation Reservation
		err := db.QueryRow("SELECT * FROM reservations WHERE event_id = ? AND sheet_id = ? AND canceled_at IS NULL", event.ID, sheet.ID).Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt)
		if err == nil {
			sheet.Mine = reservation.UserID == loginUserID
			sheet.Reserved = true
			sheet.ReservedAtUnix = reservation.ReservedAt.Unix()
		} else if err == sql.ErrNoRows {
			event.Remains++
			event.Sheets[sheet.Rank].Remains++
		} else {
			return nil, err
		}
		event.Sheets[sheet.Rank].Detail = append(event.Sheets[sheet.Rank].Detail, &sheet)
	}
	return &event, nil
}

func getEventsByIDs(eventIDs []int64, loginUserID int64) ([]*Event, error) {
	// event ids
	events := make([]*Event, 0, len(eventIDs))

	if len(eventIDs) == 0 {
		return events, nil
	}

	log.Printf("eventIDs: %d", len(eventIDs))

	var eventsIDsStr []string
	for _, value := range eventIDs {
		str := strconv.Itoa(int(value))
		eventsIDsStr = append(eventsIDsStr, str)
	}

	rows, err := db.Query("SELECT * FROM events WHERE id IN (" + strings.Join(eventsIDsStr, ",") + ")")
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
			return nil, err
		}

		event.Sheets = map[string]*Sheets{
			"S": {},
			"A": {},
			"B": {},
			"C": {},
		}

		rows2, err := db.Query("SELECT * FROM reservations WHERE event_id = ? AND canceled_at IS NULL", event.ID)
		if err != nil {
			return nil, err
		}

		reservRows := make([]Reservation, 0)
		for rows2.Next() {
			var reservation Reservation
			if err = rows2.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt); err != nil {
				return nil, err
			}
			reservRows = append(reservRows, reservation)
		}

		counter := 0
		for _, cSheet := range cachedSheets {
			sheet := *cSheet
			event.Sheets[sheet.Rank].Price = event.Price + sheet.Price
			event.Total++
			event.Sheets[sheet.Rank].Total++

			var reservation *Reservation
			for _, r := range reservRows {
				if r.SheetID == sheet.ID {
					reservation = &r
					break
				}
			}

			if reservation == nil {
				event.Remains++
				event.Sheets[sheet.Rank].Remains++
			} else {
				sheet.Mine = reservation.UserID == loginUserID
				sheet.Reserved = true
				sheet.ReservedAtUnix = reservation.ReservedAt.Unix()
			}

			// TODO: this maybe danger
			//event.Sheets[sheet.Rank].Detail = append(event.Sheets[sheet.Rank].Detail, &sheet)
			if len(eventIDs) == 1 {
				event.Sheets[sheet.Rank].Detail = append(event.Sheets[sheet.Rank].Detail, &sheet)
			}
			counter++
		}
		rows2.Close()

		events = append(events, &event)
	}

	return events, nil
}

func sanitizeEvent(e *Event) *Event {
	sanitized := *e
	sanitized.Price = 0
	sanitized.PublicFg = false
	sanitized.ClosedFg = false
	return &sanitized
}

func fillinUser(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if user, err := getLoginUser(c); err == nil {
			c.Set("user", user)
		}
		return next(c)
	}
}

func fillinAdministrator(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if administrator, err := getLoginAdministrator(c); err == nil {
			c.Set("administrator", administrator)
		}
		return next(c)
	}
}

func validateRank(rank string) bool {
	switch rank {
	case "S", "A", "B", "C":
		return true
	}
	return false
}

type Renderer struct {
	templates *template.Template
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

// initialize で メモリにのせる
func cacheSheetsOnMemory() error {
	rows, err := db.Query("SELECT * FROM sheets ORDER BY `rank`, num")
	if err != nil {
		return err
	}
	defer rows.Close()

	sheets := make([]*Sheet, 1000)

	for rows.Next() {
		var sheet Sheet
		if err := rows.Scan(&sheet.ID, &sheet.Rank, &sheet.Num, &sheet.Price); err != nil {
			return err
		}
		sheets[sheet.ID-1] = &sheet
	}
	cachedSheets = sheets
	return nil
}

func initSheetSlices() error {
	rows, err := db.Query("SELECT id FROM events")
	if err != nil {
		return err
	}
	defer rows.Close()

	// isReserved に予約済みの席を入れていく
	rows2, err := db.Query("SELECT e.id, s.id FROM events AS e JOIN reservations AS r ON e.id = r.event_id JOIN sheets AS s ON s.id = r.sheet_id WHERE e.closed_fg != 1 AND canceled_at ID NULL")
	if err != nil {
		return err
	}
	defer rows2.Close()

	isReserved := map[string]struct{}{}
	for rows2.Next() {
		var eventID, sheetID int64
		rows2.Scan(&eventID, &sheetID)
		isReserved[fmt.Sprintf("%v-%v", eventID, sheetID)] = struct{}{}
	}

	ss := map[int64]map[string][]int64{}
	for rows.Next() {
		var eventID int64
		if err := rows.Scan(&eventID); err != nil {
			log.Printf("initSheetSlices row Scan err:", err.Error())
		}

		ss[eventID] = map[string][]int64{}
		for _, sheet := range cachedSheets {
			if _, ok := isReserved[fmt.Sprintf("%v-%v", eventID, sheet.ID)]; ok { //予約済みだったらスキップ
				continue
			}
			ss[eventID][sheet.Rank] = append(ss[eventID][sheet.Rank], sheet.ID)
		}
	}

	sheetSlices = ss

	for eventID, _ := range sheetSlices {
		shuffle(eventID)
	}
	return nil
}

func cacheInitUser() error {
	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		return err
	}

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.LoginName, &user.Nickname, &user.PassHash, &user.Price); err != nil {
			return err
		}

		cacheUserMap[user.ID] = &user
	}

	return nil
}

func cacheInitAdminUser() error {
	rows, err := db.Query("SELECT * FROM administrators")
	if err != nil {
		return err
	}

	for rows.Next() {
		var admin Administrator
		if err := rows.Scan(&admin.ID, &admin.LoginName, &admin.Nickname, &admin.PassHash); err != nil {
			return err
		}

		cacheAdminUserMap[admin.ID] = &admin
	}

	return nil
}

var (
	db                *sql.DB
	cachedSheets      []*Sheet
	cacheUserMap      map[int64]*User
	cacheAdminUserMap map[int64]*Administrator

	sheetSlices      = map[int64]map[string][]int64{}
	sheetSlicesMutex = sync.RWMutex{}
)

func pushEventSheetSlices(eventID int64) {
	sheetSlicesMutex.Lock()
	defer sheetSlicesMutex.Unlock()
	sheetSlices[eventID] = map[string][]int64{}
	for _, sheet := range cachedSheets {
		sheetSlices[eventID][sheet.Rank] = append(sheetSlices[eventID][sheet.Rank], sheet.ID)
	}
	shuffle(eventID)
}

func popSheetSlices(eventID int64, rank string) (int64, bool) {
	var sheetID int64
	if len(sheetSlices[eventID][rank]) == 0 {
		return 0, false
	} else {
		sheetID = sheetSlices[eventID][rank][len(sheetSlices[eventID][rank])-1]
		sheetSlices[eventID][rank] = sheetSlices[eventID][rank][:len(sheetSlices[eventID][rank])-1]
		return sheetID, true
	}
}

func shuffle(eventID int64) {
	for _, rank := range []string{"S", "A", "B", "C"} {
		n := int64(len(sheetSlices[eventID][rank]))
		for i := n - 1; i >= 0; i-- {
			j := rand.Int63n(i + 1)
			sheetSlices[eventID][rank][i], sheetSlices[eventID][rank][j] = sheetSlices[eventID][rank][j], sheetSlices[eventID][rank][i]
		}
	}
}

func pushSheetSlices(eventID int64, rank string, sheetID int64) {
	sheetSlices[eventID][rank] = append(sheetSlices[eventID][rank], sheetID)
}

func main() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4",
		os.Getenv("DB_USER"), os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
		os.Getenv("DB_DATABASE"),
	)

	var err error
	db, err = sql.Open("mysql", dsn)
	db.SetConnMaxLifetime(0)
	db.SetMaxIdleConns(4000)
	db.SetMaxOpenConns(4000)
	if err != nil {
		log.Fatal(err)
	}

	cacheUserMap = make(map[int64]*User, 6000)
	cacheAdminUserMap = make(map[int64]*Administrator, 200)

	e := echo.New()
	funcs := template.FuncMap{
		"encode_json": func(v interface{}) string {
			b, _ := json.Marshal(v)
			return string(b)
		},
	}
	e.Renderer = &Renderer{
		templates: template.Must(template.New("").Delims("[[", "]]").Funcs(funcs).ParseGlob("views/*.tmpl")),
	}
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: os.Stderr}))
	e.Static("/", "public")
	e.GET("/", func(c echo.Context) error {
		events, err := getEvents(false)
		if err != nil {
			return err
		}
		for i, v := range events {
			events[i] = sanitizeEvent(v)
		}
		return c.Render(200, "index.tmpl", echo.Map{
			"events": events,
			"user":   c.Get("user"),
			"origin": c.Scheme() + "://" + c.Request().Host,
		})
	}, fillinUser)
	e.GET("/initialize", func(c echo.Context) error {
		cmd := exec.Command("../../db/init.sh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			return nil
		}

		if err := cacheInitUser(); err != nil {
			return err
		}

		if err := cacheInitAdminUser(); err != nil {
			return err
		}

		if err := cacheSheetsOnMemory(); err != nil {
			return err
		}

		if err := initSheetSlices(); err != nil {
			return err
		}

		return c.NoContent(204)
	})
	e.POST("/api/users", func(c echo.Context) error {
		var params struct {
			Nickname  string `json:"nickname"`
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		var user User
		if err := tx.QueryRow("SELECT * FROM users WHERE login_name = ?", params.LoginName).Scan(&user.ID, &user.LoginName, &user.Nickname, &user.PassHash, &user.Price); err != sql.ErrNoRows {
			tx.Rollback()
			if err == nil {
				return resError(c, "duplicated", 409)
			}
			return err
		}

		res, err := tx.Exec("INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, ?, ?)", params.LoginName, params.Password, params.Nickname)
		if err != nil {
			tx.Rollback()
			return resError(c, "", 0)
		}
		userID, err := res.LastInsertId()
		if err != nil {
			tx.Rollback()
			return resError(c, "", 0)
		}
		if err := tx.Commit(); err != nil {
			return err
		}

		return c.JSON(201, echo.Map{
			"id":       userID,
			"nickname": params.Nickname,
		})
	})
	e.GET("/api/users/:id", func(c echo.Context) error {
		var user User
		if err := db.QueryRow("SELECT id, nickname, price FROM users WHERE id = ?", c.Param("id")).Scan(&user.ID, &user.Nickname, &user.Price); err != nil {
			return err
		}

		loginUser, err := getLoginUser(c)
		if err != nil {
			return err
		}
		if user.ID != loginUser.ID {
			return resError(c, "forbidden", 403)
		}

		rows, err := db.Query(`SELECT
		    r.*,
		    s.rank AS sheet_rank,
		    s.num AS sheet_num
		FROM
		    reservations r
		    INNER JOIN sheets s ON s.id = r.sheet_id
		WHERE
		    r.user_id = ?
		ORDER BY
		    IFNULL (r.canceled_at, r.reserved_at) DESC
		LIMIT 5
		`, user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var recentReservations []Reservation
		for rows.Next() {
			var reservation Reservation
			var sheet Sheet
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &sheet.Rank, &sheet.Num); err != nil {
				return err
			}

			event, err := getEvent(reservation.EventID, -1)
			if err != nil {
				return err
			}

			s, ok := event.Sheets[sheet.Rank]
			if !ok {
				return sql.ErrNoRows
			}

			price := s.Price
			event.Sheets = nil
			event.Total = 0
			event.Remains = 0

			reservation.Event = event
			reservation.SheetRank = sheet.Rank
			reservation.SheetNum = sheet.Num
			reservation.Price = price
			reservation.ReservedAtUnix = reservation.ReservedAt.Unix()
			if reservation.CanceledAt != nil {
				reservation.CanceledAtUnix = reservation.CanceledAt.Unix()
			}
			recentReservations = append(recentReservations, reservation)
		}
		if recentReservations == nil {
			recentReservations = make([]Reservation, 0)
		}

		rows, err = db.Query(`SELECT
		    event_id
		FROM
		    reservations
		WHERE
		    user_id = ?
		GROUP BY
		    event_id
		ORDER BY
		    MAX(IFNULL (canceled_at, reserved_at))
		    DESC
		LIMIT 5
    `, user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		eventIDs := make([]int64, 0, 5)
		for rows.Next() {
			var eventID int64
			if err := rows.Scan(&eventID); err != nil {
				return err
			}
			eventIDs = append(eventIDs, eventID)
		}

		recentEvents, err := getEventsByIDs(eventIDs, -1)
		if err != nil {
			return err
		}

		resEvents := make([]*Event, 0, 5)
		for _, id := range eventIDs {
			for _, ev := range recentEvents {
				if ev.ID == id {
					log.Printf("%#v", *ev)
					resEvents = append(resEvents, ev)
					break
				}
			}
		}

		return c.JSON(200, echo.Map{
			"id":                  user.ID,
			"nickname":            user.Nickname,
			"recent_reservations": recentReservations,
			"total_price":         user.Price,
			"recent_events":       resEvents,
		})
	}, loginRequired)
	e.POST("/api/actions/login", func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		user := new(User)
		if err := db.QueryRow("SELECT * FROM users WHERE login_name = ?", params.LoginName).Scan(&user.ID, &user.LoginName, &user.Nickname, &user.PassHash, &user.Price); err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "authentication_failed", 401)
			}
			return err
		}

		if u, ok := cacheUserMap[user.ID]; ok {
			s := sha256.New()
			s.Write([]byte(params.Password))
			passhash := fmt.Sprintf("%x", string(s.Sum(nil)))

			if u.PassHash != passhash {
				return resError(c, "authentication_failed", 401)
			}
		} else {
			if params.Password != user.PassHash {
				return resError(c, "authentication_failed", 401)
			}
		}

		sessSetUserID(c, user.ID)
		user, err = getLoginUser(c)
		if err != nil {
			return err
		}
		return c.JSON(200, user)
	})
	e.POST("/api/actions/logout", func(c echo.Context) error {
		sessDeleteUserID(c)
		return c.NoContent(204)
	}, loginRequired)
	e.GET("/api/events", func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		for i, v := range events {
			events[i] = sanitizeEvent(v)
		}
		return c.JSON(200, events)
	})
	e.GET("/api/events/:id", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		loginUserID := int64(-1)
		if user, err := getLoginUser(c); err == nil {
			loginUserID = user.ID
		}

		events, err := getEventsByIDs([]int64{eventID}, loginUserID)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			return resError(c, "not_found", 404)
		}

		event := events[0]

		if !event.PublicFg {
			return resError(c, "not_found", 404)
		}
		return c.JSON(200, sanitizeEvent(event))
	})
	e.POST("/api/events/:id/actions/reserve", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		var params struct {
			Rank string `json:"sheet_rank"`
		}
		c.Bind(&params)

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		var event Event
		events, err := getEventsByIDs([]int64{eventID}, user.ID)

		if len(events) == 0 {
			return resError(c, "invalid_event", 404)
		}

		event = *events[0]

		if !event.PublicFg {
			return resError(c, "invalid_event", 404)
		}

		if !validateRank(params.Rank) {
			return resError(c, "invalid_rank", 400)
		}

		var sheet Sheet
		var reservationID int64
		for {

			sheetSlicesMutex.Lock()
			tx, err := db.Begin()
			if err != nil {
				return err
			}

			var sheetID int64
			if sID, ok := popSheetSlices(event.ID, params.Rank); !ok {
				sheetSlicesMutex.Unlock()
				return resError(c, "sold_out", 409)
			} else {
				sheetID = sID
				sheet = *cachedSheets[sheetID-1]
			}

			res, err := tx.Exec("INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at) VALUES (?, ?, ?, ?)", event.ID, sheetID, user.ID, time.Now().UTC().Format("2006-01-02 15:04:05.000000"))
			if err != nil {
				tx.Rollback()
				log.Println("re-try: rollback by", err)
				pushSheetSlices(event.ID, params.Rank, sheetID)
				sheetSlicesMutex.Unlock()
				continue
			}
			reservationID, err = res.LastInsertId()
			if err != nil {
				tx.Rollback()
				log.Println("re-try: rollback by", err)
				pushSheetSlices(event.ID, params.Rank, sheetID)
				sheetSlicesMutex.Unlock()
				continue
			}

			if err := tx.Commit(); err != nil {
				tx.Rollback()
				log.Println("re-try: rollback by", err)
				pushSheetSlices(event.ID, params.Rank, sheetID)
				sheetSlicesMutex.Unlock()
				continue
			}

			_, err = db.Exec("UPDATE users SET price = price + ? WHERE id = ?", sheet.Price+event.Price, user.ID)
			if err != nil {
				log.Println("re-try: rollback by", err)
			}

			break
		}
		sheetSlicesMutex.Unlock()
		return c.JSON(202, echo.Map{
			"id":         reservationID,
			"sheet_rank": params.Rank,
			"sheet_num":  sheet.Num,
		})
	}, loginRequired)
	e.DELETE("/api/events/:id/sheets/:rank/:num/reservation", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		rank := c.Param("rank")
		num, err := strconv.ParseInt(c.Param("num"), 10, 64)
		if err != nil {
			return resError(c, "invalid_sheet", 404)
		}

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		var event Event
		events, err := getEventsByIDs([]int64{eventID}, user.ID)

		if len(events) == 0 {
			return resError(c, "invalid_event", 404)
		}

		event = *events[0]

		if !event.PublicFg {
			return resError(c, "invalid_event", 404)
		}

		if !validateRank(rank) {
			return resError(c, "invalid_rank", 404)
		}

		sheet, ok := GetSheetByRankNum(rank, num)
		if !ok {
			return resError(c, "invalid_sheet", 404)
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		//sheetSlicesMutex.RLock()
		//for _, v := range sheetSlices[eventID][rank] {
		//	if v == sheet.ID {
		//		sheetSlicesMutex.RUnlock()
		//		return resError(c, "not_reserved", 400)
		//	}
		//}
		//sheetSlicesMutex.RUnlock()

		var reservation Reservation
		if err := tx.QueryRow("SELECT * FROM reservations WHERE event_id = ? AND sheet_id = ? AND canceled_at IS NULL", event.ID, sheet.ID).Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt); err != nil {
			tx.Rollback()
			if err == sql.ErrNoRows {
				return resError(c, "not_reserved", 400)
			}
			return err
		}
		if reservation.UserID != user.ID {
			sheetSlicesMutex.RLock()
			for _, v := range sheetSlices[eventID][rank] {
				if v == sheet.ID {
					sheetSlicesMutex.RUnlock()
					return resError(c, "not_reserved", 400)
				}
			}
			sheetSlicesMutex.RUnlock()
			tx.Rollback()
			return resError(c, "not_permitted", 403)
		}

		if _, err := tx.Exec("UPDATE reservations SET canceled_at = ? WHERE id = ?", time.Now().UTC().Format("2006-01-02 15:04:05.000000"), reservation.ID); err != nil {
			tx.Rollback()
			return err
		}

		if _, err := tx.Exec("UPDATE users SET price = price - ? WHERE id = ?", event.Price+sheet.Price, user.ID); err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}

		sheetSlicesMutex.Lock()
		pushSheetSlices(event.ID, rank, sheet.ID)
		sheetSlicesMutex.Unlock()

		return c.NoContent(204)
	}, loginRequired)
	e.GET("/admin/", func(c echo.Context) error {
		var events []*Event
		administrator := c.Get("administrator")
		if administrator != nil {
			var err error
			if events, err = getEvents(true); err != nil {
				return err
			}
		}
		return c.Render(200, "admin.tmpl", echo.Map{
			"events":        events,
			"administrator": administrator,
			"origin":        c.Scheme() + "://" + c.Request().Host,
		})
	}, fillinAdministrator)
	e.POST("/admin/api/actions/login", func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		administrator := new(Administrator)
		if err := db.QueryRow("SELECT * FROM administrators WHERE login_name = ?", params.LoginName).Scan(&administrator.ID, &administrator.LoginName, &administrator.Nickname, &administrator.PassHash); err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "authentication_failed", 401)
			}
			return err
		}

		if u, ok := cacheAdminUserMap[administrator.ID]; ok {
			s := sha256.New()
			s.Write([]byte(params.Password))
			passhash := fmt.Sprintf("%x", string(s.Sum(nil)))
			if u.PassHash != passhash {
				return resError(c, "authentication_failed", 401)
			}
		} else {
			if params.Password != administrator.PassHash {
				return resError(c, "authentication_failed", 401)
			}
		}

		sessSetAdministratorID(c, administrator.ID)
		administrator, err = getLoginAdministrator(c)
		if err != nil {
			return err
		}
		return c.JSON(200, administrator)
	})
	e.POST("/admin/api/actions/logout", func(c echo.Context) error {
		sessDeleteAdministratorID(c)
		return c.NoContent(204)
	}, adminLoginRequired)
	e.GET("/admin/api/events", func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		return c.JSON(200, events)
	}, adminLoginRequired)
	e.POST("/admin/api/events", func(c echo.Context) error {
		var params struct {
			Title  string `json:"title"`
			Public bool   `json:"public"`
			Price  int    `json:"price"`
		}
		c.Bind(&params)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		res, err := tx.Exec("INSERT INTO events (title, public_fg, closed_fg, price) VALUES (?, ?, 0, ?)", params.Title, params.Public, params.Price)
		if err != nil {
			tx.Rollback()
			return err
		}
		eventID, err := res.LastInsertId()
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}

		pushEventSheetSlices(eventID)

		events, err := getEventsByIDs([]int64{eventID}, -1)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			return resError(c, "not_found", 404)
		}

		event := events[0]

		return c.JSON(200, event)
	}, adminLoginRequired)
	e.GET("/admin/api/events/:id", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		var event Event
		events, err := getEventsByIDs([]int64{eventID}, -1)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			return resError(c, "not_found", 404)
		}

		event = *events[0]

		return c.JSON(200, event)
	}, adminLoginRequired)
	e.POST("/admin/api/events/:id/actions/edit", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		var params struct {
			Public bool `json:"public"`
			Closed bool `json:"closed"`
		}
		c.Bind(&params)
		if params.Closed {
			params.Public = false
		}

		var event Event
		events, err := getEventsByIDs([]int64{eventID}, -1)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			return resError(c, "not_found", 404)
		}

		event = *events[0]

		if event.ClosedFg {
			return resError(c, "cannot_edit_closed_event", 400)
		} else if event.PublicFg && params.Closed {
			return resError(c, "cannot_close_public_event", 400)
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?", params.Public, params.Closed, event.ID); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}

		var e Event
		es, err := getEventsByIDs([]int64{eventID}, -1)
		if err != nil {
			return err
		}

		if len(es) == 0 {
			return resError(c, "invalid_event", 404)
		}

		e = *es[0]

		c.JSON(200, e)
		return nil
	}, adminLoginRequired)
	e.GET("/admin/api/reports/events/:id/sales", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		var event Event
		events, err := getEventsByIDs([]int64{eventID}, -1)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			return resError(c, "invalid_event", 404)
		}

		event = *events[0]

		rows, err := db.Query("SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num, s.price AS sheet_price, e.price AS event_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.event_id = ? ORDER BY reserved_at ASC", event.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var reports []Report
		for rows.Next() {
			var reservation Reservation
			var sheet Sheet
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &sheet.Rank, &sheet.Num, &sheet.Price, &event.Price); err != nil {
				return err
			}
			report := Report{
				ReservationID: reservation.ID,
				EventID:       event.ID,
				Rank:          sheet.Rank,
				Num:           sheet.Num,
				UserID:        reservation.UserID,
				SoldAt:        reservation.ReservedAt.Format("2006-01-02T15:04:05.000000Z"),
				Price:         event.Price + sheet.Price,
			}
			if reservation.CanceledAt != nil {
				report.CanceledAt = reservation.CanceledAt.Format("2006-01-02T15:04:05.000000Z")
			}
			reports = append(reports, report)
		}
		return renderReportCSV(c, reports)
	}, adminLoginRequired)
	e.GET("/admin/api/reports/sales", func(c echo.Context) error {
		rows, err := db.Query("SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num, s.price AS sheet_price, e.id AS event_id, e.price AS event_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id ORDER BY reserved_at ASC")
		if err != nil {
			return err
		}
		defer rows.Close()

		var reports []Report
		for rows.Next() {
			var reservation Reservation
			var sheet Sheet
			var event Event
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &sheet.Rank, &sheet.Num, &sheet.Price, &event.ID, &event.Price); err != nil {
				return err
			}
			report := Report{
				ReservationID: reservation.ID,
				EventID:       event.ID,
				Rank:          sheet.Rank,
				Num:           sheet.Num,
				UserID:        reservation.UserID,
				SoldAt:        reservation.ReservedAt.Format("2006-01-02T15:04:05.000000Z"),
				Price:         event.Price + sheet.Price,
			}
			if reservation.CanceledAt != nil {
				report.CanceledAt = reservation.CanceledAt.Format("2006-01-02T15:04:05.000000Z")
			}
			reports = append(reports, report)
		}
		return renderReportCSV(c, reports)
	}, adminLoginRequired)

	e.Start(":8080")
}

type Report struct {
	ReservationID int64
	EventID       int64
	Rank          string
	Num           int64
	UserID        int64
	SoldAt        string
	CanceledAt    string
	Price         int64
}

func renderReportCSV(c echo.Context, reports []Report) error {
	body := bytes.NewBufferString("reservation_id,event_id,rank,num,price,user_id,sold_at,canceled_at\n")
	for _, v := range reports {
		body.WriteString(fmt.Sprintf("%d,%d,%s,%d,%d,%d,%s,%s\n",
			v.ReservationID, v.EventID, v.Rank, v.Num, v.Price, v.UserID, v.SoldAt, v.CanceledAt))
	}

	c.Response().Header().Set("Content-Type", `text/csv; charset=UTF-8`)
	c.Response().Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
	_, err := io.Copy(c.Response(), body)
	return err
}

func resError(c echo.Context, e string, status int) error {
	if e == "" {
		e = "unknown"
	}
	if status < 100 {
		status = 500
	}
	return c.JSON(status, map[string]string{"error": e})
}

func GetSheetByID(id int64) (Sheet, bool) {
	if 1 <= id && id <= 50 {
		return Sheet{ID: id, Rank: "S", Price: 5000, Num: id}, true
	} else if 51 <= id && id <= 150 {
		return Sheet{ID: id, Rank: "A", Price: 3000, Num: id - 50}, true
	} else if 151 <= id && id <= 500 {
		return Sheet{ID: id, Rank: "B", Price: 1000, Num: id - 200}, true
	} else if 501 <= id && id <= 1000 {
		return Sheet{ID: id, Rank: "C", Price: 0, Num: id - 500}, true
	}
	return Sheet{}, false
}

func GetSheetByRankNum(rank string, num int64) (Sheet, bool) {
	var s Sheet
	s.Num = num
	switch rank {
	case "S":
		s.ID = num
		s.Price = 5000
		s.Rank = "S"
		if !(1 <= num && num <= 50) {
			return s, false
		}
	case "A":
		s.ID = num + 50
		s.Price = 3000
		s.Rank = "A"
		if !(1 <= num && num <= 150) {
			return s, false
		}
	case "B":
		s.ID = num + 200
		s.Price = 1000
		s.Rank = "B"
		if !(1 <= num && num <= 300) {
			return s, false
		}
	case "C":
		s.ID = num + 500
		s.Price = 0
		s.Rank = "C"
		if !(1 <= num && num <= 500) {
			return s, false
		}
	default:
		return s, false
	}
	return s, true
}
