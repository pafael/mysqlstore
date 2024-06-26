mysqlstore
==========

Gorilla's Session Store Implementation for MySQL
Forked from srinathgs/mysqlstore. Only difference:
- data stored in the session encoded by GobEncoder in base64 in prod and in Json in dev 

Installation
===========

Run `go get github.com/pafael/mysqlstore` from command line. Gets installed in `$GOPATH`

Usage
=====

`NewMysqlStore` takes the following paramaters

    endpoint - A sql.Open style endpoint (with option ?parseTime=true)
    tableName - table where sessions are to be saved. Required fields are created automatically if the table doesnot exist.
    path - path for Set-Cookie header
    maxAge 
    codecs

Internally, `mysqlstore` uses [this](https://github.com/go-sql-driver/mysql) MySQL driver.

e.g.,
      

      package main
  
      import (
  	    "fmt"
  	    "github.com/srinathgs/mysqlstore"
  	    "net/http"
      )
  
      var store *mysqlstore.MySQLStore
  
      func sessTest(w http.ResponseWriter, r *http.Request) {
  	    session, err := store.Get(r, "foobar")
  	    session.Values["bar"] = "baz"
  	    session.Values["baz"] = "foo"
  	    err = session.Save(r, w)
  	    fmt.Printf("%#v\n", session)
  	    fmt.Println(err)
      }

    func main() {
        var err error
        store, err = mysqlstore.NewMySQLStore("UN:PASS@tcp(<IP>:<PORT>)/<DB>?parseTime=true&loc=Local", <tablename>, "/", 3600, []byte("<SecretKey>"))
        if err != nil {
          panic(err)
        }
        defer store.Close()

    	http.HandleFunc("/", sessTest)
    	http.ListenAndServe(":8080", nil)
    }
