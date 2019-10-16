package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type User struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
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

func getUserByID(userID int64) (*User, error) {
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

	var rows *sql.Rows
	if !all {
		rows, err = tx.Query("SELECT * FROM events WHERE public_fg = ? ORDER BY id ASC", 1)
	} else {
		rows, err = tx.Query("SELECT * FROM events ORDER BY id ASC")
	}

	// SELECT * FROM events WHERE publicFg == 1 ORDER BY id ASC

	// SELECT * FROM public_events ORDER BY id ASC
	// SELECT * FROM closed_events ORDER BY id ASC

	// SELECT * FROM events WHERE ORDER BY id ASC
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
			return nil, err
		}
		if all || event.PublicFg {
			events = append(events, &event)
		}

	}

	ids := []interface{}{}
	for _, v := range events {
		ids = append(ids, &v.ID)
	}

	r := map[int64]map[string]int{}
	rows, err = db.Query("SELECT count(*), reservations.event_id, sheets.`rank` FROM reservations "+
		"INNER JOIN sheets on reservations.sheet_id = sheets.id WHERE reservations.event_id in (?"+strings.Repeat(",?", len(ids)-1)+") AND reservations.canceled_at IS NULL group by reservations.event_id, sheets.rank;", ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var reservedCount int
		var rank string
		var eventId int64
		if err := rows.Scan(&reservedCount, &eventId, &rank); err != nil {
			return nil, err
		}
		if _, ok := r[eventId]; !ok {
			r[eventId] = map[string]int{}
			r[eventId][rank] = reservedCount
		} else {
			r[eventId][rank] = reservedCount
		}
	}
	for _, v := range events {
		v.Total = 1000
		v.Remains = 1000
		v.Sheets = getSheets(v.Price)

		for rank, counts := range r[v.ID] {
			v.Remains = v.Remains - counts
			v.Sheets[rank].Remains = v.Sheets[rank].Remains - counts
		}
	}
	return events, nil
}

func getEventById(eventID int64) (*Event, error) {
	var event Event
	if err := db.QueryRow("SELECT * FROM events WHERE id = ?", eventID).Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
		return nil, err
	}
	return &event, nil
}

func getSheets(price int64) map[string]*Sheets {
	s := map[string]*Sheets{
		"S": &Sheets{
			Price:   price + 5000,
			Total:   50,
			Remains: 50,
		},
		"A": &Sheets{
			Price:   price + 3000,
			Total:   150,
			Remains: 150,
		},
		"B": &Sheets{
			Price:   price + 1000,
			Total:   300,
			Remains: 300,
		},
		"C": &Sheets{
			Price:   price,
			Total:   500,
			Remains: 500,
		},
	}

	var i int64
	for i = 1; i <= 1000; i++ {
		sheet := getSheet(i)
		s[sheet.Rank].Detail = append(s[sheet.Rank].Detail, sheet)
	}
	return s
}
func getSheet(id int64) *Sheet {
	if id <= 50 {
		return &Sheet{
			ID:   id,
			Rank: "S",
			Num:  id,
			Price: 5000,
		}
	} else if id <= 200 {
		return &Sheet{
			ID:   id,
			Rank: "A",
			Num:  id - 50,
			Price: 3000,
		}
	} else if id <= 500 {
		return &Sheet{
			ID:   id,
			Rank: "B",
			Num:  id - 200,
			Price: 1000,
		}
	} else {
		return &Sheet{
			ID:   id,
			Rank: "C",
			Num:  id - 500,
			Price: 0,
		}
	}
}

func getSheetByNumAndRank(num int64, rank string) *Sheet {
	sheet := &Sheet{
		Rank: rank,
	}
	if rank == "S" {
		sheet.ID = num
		sheet.Num = num
	} else if rank == "A" {
		sheet.ID = num + 50
		sheet.Num = num
	} else if rank == "B" {
		sheet.ID = num + 200
		sheet.Num = num
	} else if rank == "C" {
		sheet.ID = num + 500
		sheet.Num = num
	}
	return sheet
}

func fillsEvent(event *Event, loginUserID int64) (*Event, error) {
	event.Sheets = getSheets(event.Price)
	event.Total = 1000
	event.Remains = 1000

	rows, err := db.Query("SELECT * FROM reservations WHERE reservations.event_id = ? AND reservations.canceled_at IS NULL GROUP BY event_id, sheet_id HAVING reserved_at = MIN(reserved_at)", event.ID)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var reservation Reservation
		if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt); err != nil {
			return nil, err
		}
		sheet := getSheet(reservation.SheetID)
		event.Sheets[sheet.Rank].Remains--
		event.Remains--

		sheet.Mine = reservation.UserID == loginUserID
		sheet.Reserved = true
		sheet.ReservedAtUnix = reservation.ReservedAt.Unix()
		event.Sheets[sheet.Rank].Detail[sheet.Num-1] = sheet
	}

	return event, nil
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
	return rank == "C" || rank == "B" || rank == "A" || rank == "S"
}

type Renderer struct {
	templates *template.Template
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

var db *sql.DB

var requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "http_request_count_total",
	Help: "Counter of HTTP requests made.",
}, []string{"code", "method", "path"})
var requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "http_request_duration_seconds",
	Help:    "A histogram of latencies for requests.",
	Buckets: append([]float64{0.000001, 0.001, 0.003}, prometheus.DefBuckets...),
}, []string{"code", "method", "path"})
var responseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "http_response_size_bytes",
	Help:    "A histogram of response sizes for requests.",
	Buckets: []float64{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20},
}, []string{"code", "method", "path"})

func m(action string, handler echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		res := c.Response()
		start := time.Now()

		err := handler(c)
		status := strconv.Itoa(res.Status)
		elapsed := time.Since(start).Seconds()
		bytesOut := float64(res.Size)
		requestCount.WithLabelValues(status, req.Method, action).Inc()
		requestDuration.WithLabelValues(status, req.Method, action).Observe(elapsed)
		responseSize.WithLabelValues(status, req.Method, action).Observe(bytesOut)
		return err
	}
}

func main() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4",
		os.Getenv("DB_USER"), os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
		os.Getenv("DB_DATABASE"),
	)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()

	prometheus.MustRegister(requestCount)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(responseSize)

	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

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

	e.Static("/", "public")
	e.GET("/", index(), fillinUser)
	e.GET("/initialize", initialize())
	e.POST("/api/users", m("/api/users", createUser()))
	e.GET("/api/users/:id", m("/api/users/:id", getUser()), loginRequired)
	e.POST("/api/actions/login", m("/api/actions/login", login()))
	e.POST("/api/actions/logout", m("/api/actions/logout", logout()), loginRequired)
	e.GET("/api/events", m("/api/events", getEventsHandler()))
	e.GET("/api/events/:id", m("/api/events/:id", getEventHandler()))
	e.POST("/api/events/:id/actions/reserve", m("/api/events/:id/actions/reserve", reserve()), loginRequired)
	e.DELETE("/api/events/:id/sheets/:rank/:num/reservation", m("/api/events/:id/sheets/:rank/:num/reservation", cancelReservation()), loginRequired)
	e.GET("/admin/", m("/admin/", indexAdmin()), fillinAdministrator)
	e.POST("/admin/api/actions/login", m("/admin/api/actions/login", loginAdmin()))
	e.POST("/admin/api/actions/logout", m("/admin/api/actions/logout", logoutAdmin()), adminLoginRequired)
	e.GET("/admin/api/events", m("/admin/api/events", getAdmingEvents()), adminLoginRequired)
	e.POST("/admin/api/events", m("/admin/api/events", createEvent()), adminLoginRequired)
	e.GET("/admin/api/events/:id", m("/admin/api/events/:id", getEventByAdmin()), adminLoginRequired)
	e.POST("/admin/api/events/:id/actions/edit", m("/admin/api/events/:id/actions/edit", updateEvent()), adminLoginRequired)
	e.GET("/admin/api/reports/events/:id/sales", m("/admin/api/reports/events/:id/sales", reportEventSales()), adminLoginRequired)
	e.GET("/admin/api/reports/sales", m("/admin/api/reports/sales", reportSales()), adminLoginRequired)

	//applyPprof(e)
	// applyLogger()

	e.Start(":8080")
}

func applyLogger(e *echo.Echo) {
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Output: os.Stderr}))
}

func applyPprof(e *echo.Echo) {
	pprofGroup := e.Group("/debug/pprof")
	pprofGroup.Any("/cmdline", echo.WrapHandler(http.HandlerFunc(pprof.Cmdline)))
	pprofGroup.Any("/profile", echo.WrapHandler(http.HandlerFunc(pprof.Profile)))
	pprofGroup.Any("/symbol", echo.WrapHandler(http.HandlerFunc(pprof.Symbol)))
	pprofGroup.Any("/trace", echo.WrapHandler(http.HandlerFunc(pprof.Trace)))
	pprofGroup.Any("/*", echo.WrapHandler(http.HandlerFunc(pprof.Index)))
}

func reportSales() func(c echo.Context) error {
	return func(c echo.Context) error {
		rows, err := db.Query("select r.*, e.id as event_id, e.price as event_price from reservations r inner join events e on e.id = r.event_id order by reserved_at asc for update")
		if err != nil {
			return err
		}
		defer rows.Close()

		var reports []Report
		for rows.Next() {
			var reservation Reservation
			var event Event
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &event.ID, &event.Price); err != nil {
				return err
			}

			sheet := getSheet(reservation.SheetID)
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
	}
}

func reportEventSales() func(c echo.Context) error {
	return func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		eventById, err := getEventById(eventID)
		if err != nil {
			return err
		}
		event, err := fillsEvent(eventById, -1)
		if err != nil {
			return err
		}

		rows, err := db.Query("SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num, s.price AS sheet_price, e.price AS event_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.event_id = ? ORDER BY reserved_at ASC FOR UPDATE", event.ID)
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
	}
}

func updateEvent() func(c echo.Context) error {
	return func(c echo.Context) error {
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

		eventById, err := getEventById(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}
		event, err := fillsEvent(eventById, -1)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}

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

		event.PublicFg = params.Public
		event.ClosedFg = params.Closed
		c.JSON(200, event)
		return nil
	}
}

func getEventByAdmin() func(c echo.Context) error {
	return func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		eventById, err := getEventById(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}
		event, err := fillsEvent(eventById, -1)
		if err != nil {
			return err
		}
		return c.JSON(200, event)
	}
}

func createEvent() func(c echo.Context) error {
	return func(c echo.Context) error {
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

		eventById, err := getEventById(eventID)
		if err != nil {
			return err
		}
		event, err := fillsEvent(eventById, -1)
		if err != nil {
			return err
		}
		return c.JSON(200, event)
	}
}

func getAdmingEvents() func(c echo.Context) error {
	return func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		return c.JSON(200, events)
	}
}

func logoutAdmin() func(c echo.Context) error {
	return func(c echo.Context) error {
		sessDeleteAdministratorID(c)
		return c.NoContent(204)
	}
}

func loginAdmin() func(c echo.Context) error {
	return func(c echo.Context) error {
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

		var passHash string
		if err := db.QueryRow("SELECT SHA2(?, 256)", params.Password).Scan(&passHash); err != nil {
			return err
		}
		if administrator.PassHash != passHash {
			return resError(c, "authentication_failed", 401)
		}

		sessSetAdministratorID(c, administrator.ID)
		administrator, err := getLoginAdministrator(c)
		if err != nil {
			return err
		}
		return c.JSON(200, administrator)
	}
}

func indexAdmin() func(c echo.Context) error {
	return func(c echo.Context) error {
		var events []*Event
		administrator := c.Get("administrator")
		if administrator != nil {
			var err error
			if events, err = getEvents(true); err != nil {
				return fmt.Errorf("getEvents is failed. %s", err.Error())
			}
		}
		return c.Render(200, "admin.tmpl", echo.Map{
			"events":        events,
			"administrator": administrator,
			"origin":        c.Scheme() + "://" + c.Request().Host,
		})
	}
}

func cancelReservation() func(c echo.Context) error {
	return func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		rank := c.Param("rank")
		num := c.Param("num")

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		eventById, err := getEventById(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "invalid_event", 404)
			}
			return err
		} else if !eventById.PublicFg {
			return resError(c, "invalid_event", 404)
		}

		if !validateRank(rank) {
			return resError(c, "invalid_rank", 404)
		}

		i, err := strconv.Atoi(num)
		if err != nil {
			return resError(c, "invalid_sheet", 404)
		}
		if rank == "S" && i > 50 {
			return resError(c, "invalid_sheet", 404)
		} else if rank == "A" && i > 150 {
			return resError(c, "invalid_sheet", 404)
		} else if rank == "B" && i > 300 {
			return resError(c, "invalid_sheet", 404)
		} else if rank == "C" && i > 500 {
			return resError(c, "invalid_sheet", 404)
		}

		sheet := getSheetByNumAndRank(int64(i), rank)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		var reservation Reservation
		if err := tx.QueryRow("SELECT * FROM reservations WHERE event_id = ? AND sheet_id = ? AND canceled_at IS NULL GROUP BY event_id HAVING reserved_at = MIN(reserved_at) FOR UPDATE", eventById.ID, sheet.ID).Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt); err != nil {
			tx.Rollback()
			if err == sql.ErrNoRows {
				return resError(c, "not_reserved", 400)
			}
			return err
		}
		if reservation.UserID != user.ID {
			tx.Rollback()
			return resError(c, "not_permitted", 403)
		}

		if _, err := tx.Exec("UPDATE reservations SET canceled_at = ? WHERE id = ?", time.Now().UTC().Format("2006-01-02 15:04:05.000000"), reservation.ID); err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}

		return c.NoContent(204)
	}
}

func reserve() func(c echo.Context) error {
	return func(c echo.Context) error {
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

		eventById, err := getEventById(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "invalid_event", 404)
			}
			return err
		}
		event, err := fillsEvent(eventById, user.ID)
		if err != nil {
			return err
		} else if !event.PublicFg {
			return resError(c, "invalid_event", 404)
		}

		if !validateRank(params.Rank) {
			return resError(c, "invalid_rank", 400)
		}

		var sheet Sheet
		var reservationID int64
		for {
			if err := db.QueryRow("SELECT * FROM sheets WHERE id NOT IN (SELECT sheet_id FROM reservations WHERE event_id = ? AND canceled_at IS NULL FOR UPDATE) AND `rank` = ? ORDER BY RAND() LIMIT 1", event.ID, params.Rank).Scan(&sheet.ID, &sheet.Rank, &sheet.Num, &sheet.Price); err != nil {
				if err == sql.ErrNoRows {
					return resError(c, "sold_out", 409)
				}
				return err
			}

			tx, err := db.Begin()
			if err != nil {
				return err
			}

			res, err := tx.Exec("INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at) VALUES (?, ?, ?, ?)", event.ID, sheet.ID, user.ID, time.Now().UTC().Format("2006-01-02 15:04:05.000000"))
			if err != nil {
				tx.Rollback()
				log.Println("re-try: rollback by", err)
				continue
			}
			reservationID, err = res.LastInsertId()
			if err != nil {
				tx.Rollback()
				log.Println("re-try: rollback by", err)
				continue
			}
			if err := tx.Commit(); err != nil {
				tx.Rollback()
				log.Println("re-try: rollback by", err)
				continue
			}

			break
		}
		return c.JSON(202, echo.Map{
			"id":         reservationID,
			"sheet_rank": params.Rank,
			"sheet_num":  sheet.Num,
		})
	}
}

func getEventHandler() func(c echo.Context) error {
	return func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		loginUserID := int64(-1)
		if user, err := getLoginUser(c); err == nil {
			loginUserID = user.ID
		}

		eventById, err := getEventById(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		} else if !eventById.PublicFg {
			return resError(c, "not_found", 404)
		}

		event, err := fillsEvent(eventById, loginUserID)
		if err != nil {
			return err
		}
		return c.JSON(200, sanitizeEvent(event))
	}
}

func getEventsHandler() func(c echo.Context) error {
	return func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		for i, v := range events {
			events[i] = sanitizeEvent(v)
		}
		return c.JSON(200, events)
	}
}

func logout() func(c echo.Context) error {
	return func(c echo.Context) error {
		sessDeleteUserID(c)
		return c.NoContent(204)
	}
}

func login() func(c echo.Context) error {
	return func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		user := new(User)
		if err := db.QueryRow("SELECT * FROM users WHERE login_name = ?", params.LoginName).Scan(&user.ID, &user.LoginName, &user.Nickname, &user.PassHash); err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "authentication_failed", 401)
			}
			return err
		}

		var passHash string
		if err := db.QueryRow("SELECT SHA2(?, 256)", params.Password).Scan(&passHash); err != nil {
			return err
		}
		if user.PassHash != passHash {
			return resError(c, "authentication_failed", 401)
		}

		sessSetUserID(c, user.ID)
		user, err := getLoginUser(c)
		if err != nil {
			return err
		}
		return c.JSON(200, user)
	}
}

func getUser() func(c echo.Context) error {
	return func(c echo.Context) error {
		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		rows, err := db.Query("SELECT r.* FROM reservations r WHERE r.user_id = ? ORDER BY IFNULL(r.canceled_at, r.reserved_at) DESC LIMIT 5", user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var recentReservations []Reservation
		for rows.Next() {
			var reservation Reservation
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt); err != nil {
				return err
			}

			eventById, err := getEventById(reservation.EventID)
			if err != nil {
				return err
			}
			eventById.Sheets = getSheets(eventById.Price)
			sheet := getSheet(reservation.SheetID)
			price := eventById.Sheets[sheet.Rank].Price
			eventById.Sheets = nil
			eventById.Total = 0
			eventById.Remains = 0

			reservation.Event = eventById
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

		var totalPrice int
		if err := db.QueryRow("SELECT IFNULL(SUM(e.price + s.price), 0) FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.user_id = ? AND r.canceled_at IS NULL", user.ID).Scan(&totalPrice); err != nil {
			return err
		}

		rows, err = db.Query("SELECT event_id FROM reservations WHERE user_id = ? GROUP BY event_id ORDER BY MAX(IFNULL(canceled_at, reserved_at)) DESC LIMIT 5", user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var recentEvents []*Event
		for rows.Next() {
			var eventID int64
			if err := rows.Scan(&eventID); err != nil {
				return err
			}
			eventById, err := getEventById(eventID)
			if err != nil {
				return err
			}
			event, err := fillsEvent(eventById, -1)
			if err != nil {
				return err
			}
			for k := range event.Sheets {
				event.Sheets[k].Detail = nil
			}
			recentEvents = append(recentEvents, event)
		}
		if recentEvents == nil {
			recentEvents = make([]*Event, 0)
		}

		return c.JSON(200, echo.Map{
			"id":                  user.ID,
			"nickname":            user.Nickname,
			"recent_reservations": recentReservations,
			"total_price":         totalPrice,
			"recent_events":       recentEvents,
		})
	}
}

func createUser() func(c echo.Context) error {
	return func(c echo.Context) error {
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
		if err := tx.QueryRow("SELECT * FROM users WHERE login_name = ?", params.LoginName).Scan(&user.ID, &user.LoginName, &user.Nickname, &user.PassHash); err != sql.ErrNoRows {
			tx.Rollback()
			if err == nil {
				return resError(c, "duplicated", 409)
			}
			return err
		}

		res, err := tx.Exec("INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, SHA2(?, 256), ?)", params.LoginName, params.Password, params.Nickname)
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
	}
}

func initialize() func(c echo.Context) error {
	return func(c echo.Context) error {
		cmd := exec.Command("../../db/init.sh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			return nil
		}

		return c.NoContent(204)
	}
}

func index() func(c echo.Context) error {
	return func(c echo.Context) error {
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
	}
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
	sort.Slice(reports, func(i, j int) bool { return strings.Compare(reports[i].SoldAt, reports[j].SoldAt) < 0 })

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
