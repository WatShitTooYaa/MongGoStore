# MongGoStore
Storing cookie session with mongo
Using :
- [mongo-go-driver/v2](https://github.com/mongodb/mongo-go-driver)
- [gorilla/sessions](https://github.com/gorilla/sessions)

## Description
Storing session with gorilla session then making NewMongoStore with mongo-go-driver/v2.

## Features
- NewMongoStore (using driver mongo-go-driver/v2)
- Primitive (which was removed in driver mongo-go-driver/v2)

## Installation

### Prerequisites
- Go 1.23.0 or later
- MongoDB 8.0 or later

### Steps

You can check main.go for example

1. get mongo store
   ```bash
    go get github.com/WatShitTooYaa/monggostore/mongostore
2. get primitve
    ```bash
    go get github.com/WatShitTooYaa/monggostore/primitive