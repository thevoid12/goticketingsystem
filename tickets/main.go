package main

import (
	"html/template"
	"log"
	"net/http"

	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var namefield string
var cookie http.Cookie

// var respondticket string = ""
type respondticket struct {
	problem    string
	adminreply string
}
type Page struct {
	username string
	email    string
	password string
}
type tic struct {
	U      string
	Ticks  string
	Tickid int
	Ttime  string
}
type Solu struct {
	Tid int
	Que string
	Ti  string
}

// Define salt size
const saltSize = 16

func viewHandler(w http.ResponseWriter, r *http.Request) {

	var p Page
	t, _ := template.ParseFiles("register.html")
	t.Execute(w, p)
	//fmt.Fprintf(w, "<h1>%s</h1><div>%s</div>", p.Title, p.Body)
}
func VerifyHandler(w http.ResponseWriter, r *http.Request) {

	var err error
	db, err = sql.Open("sqlite3", "./Auditticket.db")

	checkErr(err)
	//verify if the user has already registered
	entereduname := r.FormValue("username")
	enteredpassword := r.FormValue("password")

	if entereduname == "admin" && enteredpassword == "admin" { //directly going to admin panel is username and password is admin coz we are not having a database to check admin
		http.Redirect(w, r, "/Auditticket/admin", http.StatusFound)
	}
	// /*****************re hash and salt so that we can check with the db*************************/
	row := db.QueryRow("SELECT * FROM userinfo WHERE username= ?", entereduname)
	var dbuname string
	var dbemail string
	var dbhashedpassword string
	var dbsalt string
	flag := true

	if err := row.Scan(&dbuname, &dbemail, &dbhashedpassword, &dbsalt); err != nil {
		if err == sql.ErrNoRows { //if the query returns no row

			flag = false
		}

	}
	if flag == false { //username doesnt exits in database
		var p Page
		t2, _ := template.ParseFiles("gobacktoreg.html")
		t2.Execute(w, p)
	}
	/************************** recreate the hash and check with the database*************************/
	fmt.Println(dbsalt)
	hashedPassword := hashFunc(enteredpassword, []byte(dbsalt))
	fmt.Println(hashedPassword)
	if hashedPassword != dbhashedpassword {
		flag = false

	}
	if flag == true {
		namefield = entereduname

		http.Redirect(w, r, "/Auditticket/cookie", http.StatusFound)

		//divert to welcome page
	} else {

		var p Page
		t2, _ := template.ParseFiles("gobacktoreg.html")
		t2.Execute(w, p)
	}

}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	var p Page
	t1, _ := template.ParseFiles("login.html")
	t1.Execute(w, p)

	//fmt.Fprintf(w, "<h1>%s</h1><div>%s</div>", p.Title, p.Body)
}
func generateSalt(saltSize int) []byte {
	var salt = make([]byte, saltSize)
	_, err := rand.Read(salt[:])

	if err != nil {
		panic(err)
	}

	return salt
}

// Combine password and salt then hash them using the SHA-512
func hashFunc(password string, salt []byte) string {
	// Convert password string to byte slice
	var pwdByte = []byte(password)

	// Create sha-512 hasher
	var sha512 = sha512.New()

	pwdByte = append(pwdByte, salt...)

	sha512.Write(pwdByte)

	// Get the SHA-512 hashed password
	var hashedPassword = sha512.Sum(nil)

	// Convert the hashed to hex string
	var hashedPasswordHex = hex.EncodeToString(hashedPassword)
	return hashedPasswordHex
}
func saveHandler(w http.ResponseWriter, r *http.Request) {
	//title := r.URL.Path[len("/save/"):]
	uname := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirm_password := r.FormValue("confirm_password")
	var err error
	db, err = sql.Open("sqlite3", "./Auditticket.db")
	checkErr(err)
	createquery := `CREATE TABLE IF NOT EXISTS userinfo(
        "username" VARCHAR(64) NULL,
        "email" VARCHAR(64) NULL,
        "password" VARCHAR(64) NULL,
		"saltstring" VARCHAR(64) NULL
    )`
	create, err := db.Prepare(createquery)
	checkErr(err)
	create.Exec()
	row := db.QueryRow("SELECT * FROM userinfo WHERE username= ?", uname)
	var dbuname string
	var dbupassword string
	var dbemail string
	var dbsalt string
	flag := false
	if err := row.Scan(&dbuname, &dbemail, &dbupassword, &dbsalt); err != nil {
		if err == sql.ErrNoRows { //if the query returns no row

			flag = true
		}

	}

	if password != confirm_password {
		//passworderr(w http.ResponseWriter,r *http.Request)
		//createing a templete to display password and confirm password doesnt match
		var p Page
		t0, _ := template.ParseFiles("passworderr.html")
		t0.Execute(w, p)
	} else if flag == false { //this part is not working bug
		//usernameerr()
		//if the username already exists
		var p Page
		t1, _ := template.ParseFiles("usernameerr.html")
		t1.Execute(w, p)
	} else {

		//insert
		stmt, err := db.Prepare("INSERT INTO userinfo(username, email,password,saltstring) values(?,?,?,?)")
		checkErr(err)
		/*******************hash and salt the password. store the salt also in the database********************************/
		var salt = generateSalt(saltSize)

		// Hash password
		hashedPassword := hashFunc(password, salt)
		saltstring := string(salt[:])
		res, err := stmt.Exec(uname, email, hashedPassword, saltstring)
		fmt.Println(res)

		checkErr(err)
		http.Redirect(w, r, "/Auditticket/login", http.StatusFound)
	}
	/*	rows, err := db.Query("SELECT * FROM userinfo")
				checkErr(err)
		``
				var u string
				var e string
				var p string
				for rows.Next() {
					err = rows.Scan(&u, &e, &p)
					checkErr(err)
					fmt.Println(u)
					fmt.Println(e)
					fmt.Println(p)

				}*/

}
func CookieHandler(w http.ResponseWriter, r *http.Request) {
	//set cookies
	//creating a unique id field for both cookie and cookiemanage db
	/**********************setting cookie **************************/
	us, err := exec.Command("uuidgen").Output()
	if err != nil {

		log.Fatal(err)
	}
	uniqueval := fmt.Sprintf("%s", us) //convert byte into string

	// creating a cookie
	cookie = http.Cookie{
		Name:     namefield, //namefield is created as a global variable
		Value:    uniqueval,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	/*****************************creating a table in the existing db to store name and the cookie id value*****/
	createquery := `CREATE TABLE IF NOT EXISTS cookiemanager(
		"username" VARCHAR(64) NULL,"cookieid" VARCHAR(64) NULL)`
	create, err := db.Prepare(createquery)

	checkErr(err)
	create.Exec()

	// insert
	stmt, err := db.Prepare("INSERT OR REPLACE INTO cookiemanager(username,cookieid) values(?,?)")

	checkErr(err)

	res, err := stmt.Exec(namefield, uniqueval)
	fmt.Println(res)

	checkErr(err)
	rows, err := db.Query("SELECT * FROM cookiemanager")

	checkErr(err)

	var u string
	var e string

	for rows.Next() {
		err = rows.Scan(&u, &e)
		checkErr(err)
		fmt.Println(u)
		fmt.Println(e)

	}
	//redirect to some other page to start the session
	http.Redirect(w, r, "/Auditticket/welcome", http.StatusFound)

}
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	/*****************open up a session if the cookie's value and cookie id value in db matches***********/

	//fetch cookie value from the cookie
	fmt.Println(namefield)
	cookies, err := r.Cookie(namefield)
	if err != nil {

		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	cookievalue := cookies.Value
	fmt.Println(cookievalue)

	//search this cookie value in the cookiemanager db
	row := db.QueryRow("SELECT * FROM userinfo WHERE username= ?", namefield)
	var dbnamefield string

	flag := true
	if err := row.Scan(&dbnamefield); err != nil {
		if err == sql.ErrNoRows { //if the query returns no row then session is off

			flag = false
		}

	}
	if flag == true { //session open
		//fmt.Fprintf(w, "WELCOME PAGE")
		var p Page

		t3, _ := template.ParseFiles("welcome.html")
		t3.Execute(w, p)
		t4, _ := template.ParseFiles("logout.html")
		t4.Execute(w, p)
		ticket := r.FormValue("ticket") //receive from the form welcome.html
		fmt.Println(ticket)
		//creating a db to store the username and ticket
		if ticket != "" {
			storeticket(ticket)
		}
	} else { //sesson closed so go back to login or register

	}

}

func storeticket(ticket string) {
	/*****************************creating a table in the existing db to store name and their ticket*****/

	createquery := `CREATE TABLE IF NOT EXISTS ticketmanager(
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,"username" VARCHAR(64) NULL,"ticket" VARCHAR(64) NULL,"time" TIMESTAMP)`
	create, err := db.Prepare(createquery)

	checkErr(err)
	create.Exec()

	// insert
	//stmt, err := db.Prepare("INSERT INTO ticketmanager(username,ticket,when) values(?,?,?)")
	stmt, err := db.Prepare("INSERT INTO ticketmanager(username,ticket,time) values(?,?,?)")
	checkErr(err)
	if ticket != "" {
		//res, err := stmt.Exec(namefield, ticket, time.Now().Format("01-02-2006 15:04:05"))
		res, err := stmt.Exec(namefield, ticket, time.Now())

		fmt.Println(res)
		checkErr(err)
	}
	/*stmt1, err := db.Prepare("delete from ticketmanager")
	checkErr(err)

	res1, err := stmt1.Exec()
	fmt.Println(res1)*/
	rows, err := db.Query("SELECT * FROM ticketmanager")
	fmt.Println(rows)
	checkErr(err)

	var u int
	var e string
	var a string
	var t time.Time
	for rows.Next() {
		err = rows.Scan(&u, &e, &a, &t)
		checkErr(err)
		fmt.Println(u)
		fmt.Println(e)
		fmt.Println(a)
		fmt.Println(t)

	}

}
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	/*****************open up a session if the cookie's value and cookie id value in db matches***********/

	//fetch cookie value from the cookie

	cookies, err := r.Cookie(namefield)
	if err != nil {

		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	cookievalue := cookies.Value
	fmt.Println(cookievalue)
	//delete the cookie
	cookie.MaxAge = -1
	http.SetCookie(w, &cookie)
	stmt, err := db.Prepare("delete from cookiemanager where username=?")
	checkErr(err)

	res, err := stmt.Exec(namefield)
	fmt.Println(res)
	checkErr(err)
	//fmt.Println("after deleting in cookiemanager db")
	var u string
	var e string
	rows, err := db.Query("SELECT * FROM cookiemanager")
	for rows.Next() {
		err = rows.Scan(&u, &e)
		checkErr(err)
		fmt.Println(u)
		fmt.Println(e)

	}
	//redirecting to login page after logout
	http.Redirect(w, r, "/Auditticket/login", http.StatusFound)
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {

	var ids int
	var u string
	var e string
	var t time.Time

	/*usernamemap := make(map[string][]string)
	ticketidmap := make(map[string][]int)
	problemmap := make(map[string][]string)*/
	//r.ParseForm()
	// printticket = r.Form["ticket"][0]
	// pid, _ := strconv.ParseInt(r.Form["ticketid"][0], 10, 64)

	rows, err := db.Query("SELECT * FROM ticketmanager ORDER BY time DESC")
	for rows.Next() {
		err = rows.Scan(&ids, &u, &e, &t)
		checkErr(err)
		/*	usernamemap[u] = append(usernamemap[u], u) //map with value as a array
			ticketidmap[u] = append(ticketidmap[u], ids)
			problemmap[u] = append(problemmap[u], e)*/
		s := t.Format("2006-01-02 15:04:05")
		tpointer := &tic{Tickid: ids, U: u, Ticks: e, Ttime: s}
		fmt.Println(e)
		fmt.Println(t)
		t4, _ := template.ParseFiles("adminview.html")
		t4.Execute(w, tpointer)
	}
}
func AdminChatHandler(w http.ResponseWriter, r *http.Request) {

	var ids int
	var u string
	var e string
	var t time.Time
	printusername := r.FormValue("username")
	pid, _ := strconv.ParseInt(r.FormValue("ticketid"), 10, 64)
	//printticket = r.FormValue("ticket") //solution given by admin
	rows, err := db.Query("SELECT * FROM ticketmanager where username =? and id=?", printusername, pid)
	for rows.Next() {
		err = rows.Scan(&ids, &u, &e, &t)
		checkErr(err)
		s := t.Format("2006-01-02 15:04:05")
		tpointer := &tic{Tickid: ids, U: u, Ticks: e, Ttime: s}
		fmt.Println(ids)
		fmt.Println(u)
		fmt.Println(e)
		fmt.Println(t)
		t4, _ := template.ParseFiles("adminview1.html")
		t4.Execute(w, tpointer)

	}

}
func AdminChatArchiveHandler(w http.ResponseWriter, r *http.Request) {
	var printticket string
	var printticketid int64
	printusername := r.FormValue("username")
	pid, _ := strconv.ParseInt(r.FormValue("ticketid"), 10, 64)
	printticketid = pid
	printticket = r.FormValue("ticket")        //solution given by admin
	printcomplaint := r.FormValue("complaint") //complaint by the user
	createquery := `CREATE TABLE IF NOT EXISTS adminmanager(
		"id" INTEGER PRIMARY KEY AUTOINCREMENT,"ticketid" INTEGER,"username" VARCHAR(64) NULL,"ticket" VARCHAR(64) NULL)`
	create, err := db.Prepare(createquery)

	checkErr(err)
	create.Exec()
	type So struct {
		Tid int64
		Que string
		Ti  string
	}
	// insert
	//stmt, err := db.Prepare("INSERT INTO ticketmanager(username,ticket,when) values(?,?,?)")
	stmt, err := db.Prepare("INSERT INTO adminmanager(ticketid,username,ticket) values(?,?,?)")
	checkErr(err)
	if printticket != "" {

		res, err := stmt.Exec(printticketid, printusername, printticket)
		fmt.Println(res)
		fmt.Println(printusername)
		fmt.Println(printticket)
		checkErr(err)
		s := &So{Tid: printticketid, Que: printcomplaint, Ti: printticket}
		t4, _ := template.ParseFiles("adminview2.html")
		t4.Execute(w, s)
	}

	var p Page
	t5, _ := template.ParseFiles("logout1.html")
	t5.Execute(w, p)

}
func TicketHandler(w http.ResponseWriter, r *http.Request) {
	/**************************************retrieve all the replies by by the admin and ticket raised**************/

	rows, err := db.Query("SELECT * FROM ticketmanager where username=?", namefield)
	var ids int
	var id1 int
	var i int
	var u string
	var u1 string
	var e string
	var t string
	var ti time.Time
	for rows.Next() {
		err = rows.Scan(&ids, &u, &e, &ti)
		checkErr(err)
		rows1, err := db.Query("SELECT * FROM adminmanager where ticketid=?", ids)
		for rows1.Next() {
			err = rows1.Scan(&i, &id1, &u1, &t)
			checkErr(err)
			//Ticketid int
			//Ticket string
			//fmt.Println(id1)
			//fmt.Println(e)
			//fmt.Println(t)
			re1 := &Solu{Tid: id1, Que: e, Ti: t}
			//tpointer := &tic{ Tickid: ids,Un: u, Tick: e}
			t7, _ := template.ParseFiles("raisedticket.html")
			t7.Execute(w, re1)
		}
	}

	/**********************************************************************************************************************/
}

func CommonLogoutHandler(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, "/Auditticket/adminchat", http.StatusFound)

}
func main() {
	http.HandleFunc("/Auditticket/register", viewHandler)
	http.HandleFunc("/Auditticket/savetodb", saveHandler)
	http.HandleFunc("/Auditticket/login", loginHandler)
	http.HandleFunc("/Auditticket/verify", VerifyHandler)
	http.HandleFunc("/Auditticket/cookie", CookieHandler)
	http.HandleFunc("/Auditticket/welcome", WelcomeHandler)
	http.HandleFunc("/Auditticket/raisedtickets", TicketHandler)
	http.HandleFunc("/Auditticket/logout", LogoutHandler)
	http.HandleFunc("/Auditticket/logout1", CommonLogoutHandler)
	http.HandleFunc("/Auditticket/adminchat", AdminChatHandler)
	http.HandleFunc("/Auditticket/adminarchive", AdminChatArchiveHandler)
	http.HandleFunc("/Auditticket/admin", AdminHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
