package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"event-response-app/internal/auth"
	"event-response-app/internal/fastschema"
)

var (
	fsClient *fastschema.Client
	tpls    *template.Template
)

func main() {
	baseURL := os.Getenv("FASTSCHEMA_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8000"
	}
	adminUser := os.Getenv("FASTSCHEMA_ADMIN_USER")
	adminPass := os.Getenv("FASTSCHEMA_ADMIN_PASS")
	fsClient = fastschema.NewClient(baseURL, "event", adminUser, adminPass)

	var err error
	tpls, err = template.ParseGlob("web/templates/*.html")
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)

	// Prior Cognito by default: auth only when COGNITO_USER_POOL_ID is set (e.g. by event_dash_auth).
	// Existing stacks (event_dash, event_dash_external) do not set it, so no behavior change.
	cognitoEnabled := os.Getenv("COGNITO_USER_POOL_ID") != ""
	if cognitoEnabled {
		// Protected routes: require auth and permission
		mux.Handle("/", auth.Middleware(auth.RequirePermission("view")(http.HandlerFunc(listHandler))))
		mux.Handle("/edit", auth.Middleware(auth.RequirePermission("view")(http.HandlerFunc(editFormHandler))))
		mux.Handle("/delete", auth.Middleware(auth.RequirePermission("view")(http.HandlerFunc(deleteConfirmHandler))))
		mux.Handle("/new", auth.Middleware(auth.RequirePermission("write")(http.HandlerFunc(newFormHandler))))
		mux.Handle("/create", auth.Middleware(auth.RequirePermission("write")(http.HandlerFunc(createHandler))))
		mux.Handle("/update", auth.Middleware(auth.RequirePermission("write")(http.HandlerFunc(updateHandler))))
		mux.Handle("/delete/confirm", auth.Middleware(auth.RequirePermission("write")(http.HandlerFunc(deleteHandler))))
		mux.HandleFunc("/forbidden", forbiddenHandler)
		mux.Handle("/whoami", auth.Middleware(http.HandlerFunc(whoamiHandler)))
	} else {
		mux.HandleFunc("/", listHandler)
		mux.HandleFunc("/new", newFormHandler)
		mux.HandleFunc("/create", createHandler)
		mux.HandleFunc("/edit", editFormHandler)
		mux.HandleFunc("/update", updateHandler)
		mux.HandleFunc("/delete", deleteConfirmHandler)
		mux.HandleFunc("/delete/confirm", deleteHandler)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if cognitoEnabled {
		log.Printf("Listening on :%s (FASTSCHEMA_URL=%s, Cognito auth enabled)", port, baseURL)
	} else {
		log.Printf("Listening on :%s (FASTSCHEMA_URL=%s)", port, baseURL)
	}
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	events, err := fsClient.List()
	if err != nil {
		log.Printf("list: %v", err)
		events = []fastschema.Event{}
	}
	if events == nil {
		events = []fastschema.Event{}
	}
	createdID := r.URL.Query().Get("created")
	listError, _ := url.QueryUnescape(r.URL.Query().Get("error"))
	if listError == "" && err != nil {
		listError = listErrorMessage(err)
	}
	data := map[string]interface{}{
		"Events":    events,
		"Created":   createdID,
		"ListError": listError,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpls.ExecuteTemplate(w, "list.html", data); err != nil {
		log.Printf("template: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

// listErrorMessage returns a user-facing message for a List() error.
func listErrorMessage(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "401"):
		return "Authentication failed. Set FASTSCHEMA_ADMIN_USER and FASTSCHEMA_ADMIN_PASS (or create an admin user in FastSchema)."
	case strings.Contains(s, "403") || strings.Contains(s, "404"):
		return "Access denied or event schema not found. Create the “event” schema in the FastSchema dashboard and ensure the admin user has access."
	case strings.Contains(s, "connection refused") || strings.Contains(s, "dial"):
		return "Could not reach FastSchema. Ensure it is running and FASTSCHEMA_URL is correct."
	default:
		return "Could not load events. Ensure FastSchema is running and the event schema exists."
	}
}

// crudErrorMessage returns a user-facing message for create/update/delete errors.
func crudErrorMessage(op string, err error) string {
	s := err.Error()
	prefix := "Could not " + op + " event. "
	switch {
	case strings.Contains(s, "401"):
		return prefix + "Authentication failed. Set FASTSCHEMA_ADMIN_USER and FASTSCHEMA_ADMIN_PASS (or create an admin user in FastSchema)."
	case strings.Contains(s, "403") || strings.Contains(s, "404") || strings.Contains(s, "not found"):
		return prefix + "Create the \"event\" schema in the FastSchema dashboard and ensure the admin user has access."
	case strings.Contains(s, "connection refused") || strings.Contains(s, "dial"):
		return prefix + "Ensure FastSchema is running and FASTSCHEMA_URL is correct."
	default:
		return prefix + "Ensure FastSchema is running and the event schema exists."
	}
}

func newFormHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpls.ExecuteTemplate(w, "form.html", map[string]interface{}{"Event": fastschema.Event{}, "Action": "/create", "Title": "New Event"}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad form", http.StatusBadRequest)
		return
	}
	e := fastschema.Event{
		Title:       r.FormValue("title"),
		Description: r.FormValue("description"),
	}
	created, err := fsClient.Create(e)
	if err != nil {
		log.Printf("create: %v", err)
		http.Redirect(w, r, "/?error="+url.QueryEscape(crudErrorMessage("create", err)), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?created="+strconv.Itoa(created.ID), http.StatusSeeOther)
	return
}

func editFormHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	e, err := fsClient.Get(id)
	if err != nil {
		log.Printf("get: %v", err)
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpls.ExecuteTemplate(w, "form.html", map[string]interface{}{"Event": e, "Action": "/update", "Title": "Edit Event"}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad form", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	e := fastschema.Event{
		ID:          id,
		Title:       r.FormValue("title"),
		Description: r.FormValue("description"),
	}
	_, err = fsClient.Update(id, e)
	if err != nil {
		log.Printf("update: %v", err)
		http.Redirect(w, r, "/?error="+url.QueryEscape(crudErrorMessage("update", err)), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteConfirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	e, err := fsClient.Get(id)
	if err != nil {
		log.Printf("get: %v", err)
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpls.ExecuteTemplate(w, "delete.html", e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad form", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := fsClient.Delete(id); err != nil {
		log.Printf("delete: %v", err)
		http.Redirect(w, r, "/?error="+url.QueryEscape(crudErrorMessage("delete", err)), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func forbiddenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>You do not have permission to access this resource.</p></body></html>`)
}

func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "User:\n  Sub: %s\n  Email: %s\n  Groups: %v\nPermissions:\n", user.Sub, user.Email, user.Groups)
	for perm, granted := range user.Permissions {
		if granted {
			fmt.Fprintf(w, "  %s: true\n", perm)
		}
	}
}
