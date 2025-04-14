package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/atmosone/goard"
	_ "github.com/lib/pq"
)

var stub Account = Account{
	ID: 1,
}

type Account struct {
	ID int64
}

func (a *Account) GetID() int64 {
	return a.ID
}

type App struct {
	goard.App
}

func (a *App) CreateAccount(ctx context.Context, account json.RawMessage) (goard.Account, error) {
	return &stub, nil
}

func (a *App) AccountByID(ctx context.Context, id int64) (goard.Account, error) {
	return &stub, nil
}

func (a *App) DeleteAccount(ctx context.Context, id int64) error {
	return nil
}

func main() {
	db, err := sql.Open("postgres",
		"postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
	)

	if err != nil {
		panic(err)
	}

	g := goard.New(&goard.Config{
		App: &App{},
		Admin: goard.Admin{
			Login:    "admin",
			Password: "123456",
		},
		Transport: goard.NewJSONTransport(),
		Container: goard.NewCookiesContainer("ejournal"),
		Hasher:    goard.NewBcryptHasher(goard.DEFAULT_COST),
		Validator: goard.NewDefaultValidator(),
		Store:     goard.NewStore(),
		Database:  goard.NewPostgresDatabase(db),
		TTL:       5 * time.Hour,
		CI:        10 * time.Second,
	})

	http.HandleFunc("/signin", g.SignIn)
	http.HandleFunc("/signup", g.SignUp)
	http.HandleFunc("/signout", g.SignOut)
	http.Handle("/", g.Guard(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

		}),
		func(s *goard.Session) bool {
			return slices.Contains(s.Roles(), "admin")
		}),
	)

	if err := g.Open(); err != nil {
		panic(err)
	}

	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Println(err)
		}
	}()

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	<-exit
}
