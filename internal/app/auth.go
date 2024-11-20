package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"past-papers-web/templates"
	"time"
)

func (a *App) Register(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	name := r.FormValue("name")
	studentId := r.FormValue("studentId")

	// Validate required fields
	for _, v := range []string{email, name, studentId} {
		if v == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}
	}

	// Generate OTP and store it in cache
	otp := generateOTP()
	a.otpCache.Set(email, otp, 5*time.Minute)

	// Set cookies
	cookies := []*http.Cookie{
		{
			Name:     "email",
			Value:    email,
			MaxAge:   3600,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "name",
			Value:    name,
			MaxAge:   3600,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "studentId",
			Value:    studentId,
			MaxAge:   3600,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
	}

	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}

	// Send OTP email to user
	t, err := template.ParseFiles("templates/mail/otp.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf := new(bytes.Buffer)
	data := map[string]interface{}{"Name": name, "OTP": otp}
	if err = t.Execute(buf, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.mailer.Send(email, "OTP Verification", buf.String())
}

func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		http.SetCookie(w, &http.Cookie{ // Set a cookie
			Name:     "email",
			Value:    email,
			MaxAge:   3600,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		})

		if _, ok := a.usercache.Get(email); ok { // Has user in cache
			http.Redirect(w, r, "/content", http.StatusSeeOther)
			return
		}
		if a.helper.CheckUser(email) { // Has user in DB
			a.usercache.Set(email, true, time.Duration(time.Hour*720)) // Set cache for 30 days
			http.Redirect(w, r, "/content", http.StatusSeeOther)
			return
		}

		templates.Render(w, "entry.html", nil)
		return
	}
	templates.Render(w, "entry.html", nil)
	return
}

func generateOTP() string {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (a *App) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Validate OTP
	otpInput := r.FormValue("otp")
	if otpInput == "" {
		http.Error(w, "OTP is missing", http.StatusBadRequest)
		return
	}
	emailCookie, err := r.Cookie("email")
	if err != nil {
		http.Error(w, "Email cookie is missing", http.StatusBadRequest)
		return
	}
	email := emailCookie.Value
	storedOTP, ok := a.otpCache.Get(email)
	if !ok || storedOTP != otpInput {
		http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
		return
	}
	a.otpCache.Delete(email)

	// Register the user
	nameCookie, err := r.Cookie("name")
	if err != nil {
		http.Error(w, "Name cookie is missing", http.StatusBadRequest)
		return
	}
	name := nameCookie.Value
	studentIdCookie, err := r.Cookie("studentId")
	if err != nil {
		http.Error(w, "Student ID cookie is missing", http.StatusBadRequest)
		return
	}
	studentId := studentIdCookie.Value
	success := a.helper.RegisterUser(email, name, studentId)
	if !success {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Registration was successful
	clearCookies := []string{"name", "studentId"}
	for _, cookieName := range clearCookies {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // Clear cookie by setting MaxAge to -1
			SameSite: http.SameSiteLaxMode,
			HttpOnly: true,
		})
	}
	w.WriteHeader(http.StatusOK)
}
