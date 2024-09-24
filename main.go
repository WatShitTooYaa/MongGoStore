package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/WatShitTooYaa/monggostore/mongostore"

	// "github.com/TykTechnologies/mongostore"
	gcon "github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	gubrak "github.com/novalagung/gubrak/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type M map[string]interface{}

var sc = securecookie.New([]byte("very-secret"), []byte("a-lot-secret-yay"))

const SESSION_ID = "id"

func setCookie(c echo.Context, name string, data M) error {
	encoded, err := sc.Encode(name, data)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    encoded,
		Path:     "/",
		Secure:   false,
		HttpOnly: true,
		Expires:  time.Now().Add(1 * time.Hour),
	}

	http.SetCookie(c.Response(), cookie)

	return nil
}

func getCookie(c echo.Context, name string) (M, error) {
	cookie, err := c.Request().Cookie(name)
	if err == nil {
		data := M{}

		if err = sc.Decode(name, cookie.Value, &data); err == nil {
			return M{"data": data, "cookie": cookie.Value}, nil
		}
	}

	return nil, err
}

func deleteCookie(c echo.Context, name string) {
	// encoded, err := sc.Encode(name, data)

	cookie := &http.Cookie{
		Name:    name,
		MaxAge:  -1,
		Path:    "/",
		Expires: time.Unix(0, 0),
	}

	http.SetCookie(c.Response(), cookie)

	// return nil
}

func newMongoStore(ctx context.Context, disconMongo chan bool) *mongostore.MongoStore {
	// db := "mongodb://localhost:27107"
	// mgoSession, err := mgo.Dial("mongodb://localhost:27017/test")

	client, err := mongo.Connect(options.Client().ApplyURI("mongodb://localhost:27017"))
	go func() {
		<-disconMongo
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
		fmt.Println("mongo disconnected")
	}()

	if err != nil {
		log.Println("Error", err)
		os.Exit(0)
	}
	fmt.Println("success")

	dbCollection := client.Database("learnwebgolang").Collection("session")

	maxAge := 86400 * 7
	// ensureTTL := true
	authKey := []byte("my-auth-key-very-secret")
	encryptionKey := []byte("my-encryption-key-very-secret123")

	store := mongostore.NewMongoStore(
		dbCollection,
		&sessions.Options{
			MaxAge: maxAge,
			Secure: false,
		},
		authKey,
		encryptionKey,
	)

	return store
}

func main() {
	const CookieName = "data"
	disconMongo := make(chan bool)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// newMongoStore(ctx)
	store := newMongoStore(ctx, disconMongo)
	defer func() {
		disconMongo <- true
	}()

	e := echo.New()

	e.Use(echo.WrapMiddleware(gcon.ClearHandler))

	e.GET("/home", func(c echo.Context) error {
		dataId, err := getCookie(c, "id")
		if err != nil && err != http.ErrNoCookie && err != securecookie.ErrMacInvalid {
			return err
		}

		dataCN, err := getCookie(c, CookieName)
		if err != nil && err != http.ErrNoCookie && err != securecookie.ErrMacInvalid {
			return err
		}
		data := bson.M{
			"id": dataId,
			"CN": dataCN,
		}
		return c.JSON(http.StatusOK, data)
	})

	e.GET("/index", func(c echo.Context) error {
		data, err := getCookie(c, CookieName)
		if err != nil && err != http.ErrNoCookie && err != securecookie.ErrMacInvalid {
			return err
		}

		if data == nil {
			data = M{"message": "Hello!!", "ID": gubrak.RandomString(32)}

			err = setCookie(c, CookieName, data)
			if err != nil {
				return err
			}
		}

		return c.JSON(http.StatusOK, data)
	})

	e.GET("/del", func(c echo.Context) error {
		// data, err := getCookie(c, CookieName)
		// if err != nil {
		// 	return err
		// }
		// if data == nil {
		// 	return c.JSON(http.StatusOK, "cookie is not setted yet")
		// }

		deleteCookie(c, "id")
		deleteCookie(c, CookieName)

		return c.JSON(http.StatusOK, "success delete cookie")
	})

	e.GET("/set", func(c echo.Context) error {
		session, err := store.Get(c.Request(), SESSION_ID)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error getting session: %v", err))
		}
		session.Values["message1"] = "hello"
		session.Values["message2"] = "world"

		err = session.Save(c.Request(), c.Response())
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error saving session: %v", err))
		}

		return c.Redirect(http.StatusTemporaryRedirect, "/get")
	})

	e.GET("/get", func(c echo.Context) error {
		session, err := store.Get(c.Request(), SESSION_ID)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error getting session: %v", err))
		}
		if len(session.Values) == 0 {
			return c.String(http.StatusOK, "empty result")
		}

		return c.String(http.StatusOK, fmt.Sprintf(
			"%s %s", session.Values["message1"], session.Values["message2"],
		))
	})

	e.GET("/delete", func(c echo.Context) error {
		session, err := store.Get(c.Request(), SESSION_ID)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error deleting session: %v", err))
		}

		session.Options.MaxAge = -1
		err = session.Save(c.Request(), c.Response())
		if err != nil {
			fmt.Println("Error saving session: ", err)
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error saving when deleting session: %v", err))
		}

		fmt.Println("Session deleted and saved successfully, redirecting...")
		return c.Redirect(http.StatusTemporaryRedirect, "/get")
	})

	e.Logger.Fatal(e.Start(":9000"))

	close(disconMongo)
}
