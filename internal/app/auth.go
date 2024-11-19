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

	// 設置用戶 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "email",
		Value:    email,
		MaxAge:   3600,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	// 验证必要字段
	for _, v := range []string{email, name, studentId} {
		if v == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}
	}

	// 生成 OTP 并存储到缓存
	otp := generateOTP()
	a.otpCache.Set(email, otp, 5*time.Minute)

	// 发送邮件
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
	w.Write([]byte("Success, please check your email for the OTP."))
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
	// 解析请求体
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// 获取表单数据
	otpInput := r.FormValue("otp")
	if otpInput == "" {
		http.Error(w, "OTP is missing", http.StatusBadRequest)
		return
	}

	// 检查 Cookie
	cookie, err := r.Cookie("email")
	if err != nil {
		http.Error(w, "Email cookie is missing", http.StatusBadRequest)
		return
	}
	email := cookie.Value

	// 验证 OTP
	storedOTP, ok := a.otpCache.Get(email)
	if !ok || storedOTP != otpInput {
		http.Error(w, "Invalid or expired OTP", http.StatusUnauthorized)
		return
	}

	// 验证成功
	a.otpCache.Delete(email)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OTP verified successfully"))
}
