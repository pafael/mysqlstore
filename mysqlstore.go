/*
	Gorilla Sessions backend for MySQL.

Copyright (c) 2013 Contributors. See the list of contributors in the CONTRIBUTORS file for details.

This software is licensed under a MIT style license available in the LICENSE file.
*/
package mysqlstore

import (
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type MySQLStore struct {
	db         *sql.DB
	stmtInsert *sql.Stmt
	stmtDelete *sql.Stmt
	stmtUpdate *sql.Stmt
	stmtSelect *sql.Stmt

	Codecs  []securecookie.Codec
	Options *sessions.Options
	table   string
	Json bool
}

type sessionRow struct {
	id         string
	data       []byte
	createdOn  time.Time
	modifiedOn time.Time
	expiresOn  time.Time
}

// endpoint string shoud have option "parseTime=true" for this package to work with mariadb
func NewMySQLStore(endpoint string, tableName string, path string, maxAge int, keyPairs ...[]byte) (*MySQLStore, error) {
	db, err := sql.Open("mysql", endpoint)
	if err != nil {
		return nil, err
	}

	return NewMySQLStoreFromConnection(db, tableName, path, maxAge, keyPairs...)
}

func NewMySQLStoreFromConnection(db *sql.DB, tableName string, path string, maxAge int, keyPairs ...[]byte) (*MySQLStore, error) {
	// Make sure table name is enclosed.
	tableName = "`" + strings.Trim(tableName, "`") + "`"

	cTableQ := "CREATE TABLE IF NOT EXISTS " +
		tableName + " (id INT NOT NULL AUTO_INCREMENT, " +
		"session_data BLOB, " +
		"created_on TIMESTAMP DEFAULT NOW(), " +
		"modified_on TIMESTAMP NOT NULL DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP, " +
		"expires_on TIMESTAMP DEFAULT NOW(), PRIMARY KEY(`id`)) ENGINE=InnoDB;"
	if _, err := db.Exec(cTableQ); err != nil {
		switch err.(type) {
		case *mysql.MySQLError:
			// Error 1142 means permission denied for create command
			if err.(*mysql.MySQLError).Number == 1142 {
				break
			} else {
				return nil, err
			}
		default:
			return nil, err
		}
	}

	insQ := "INSERT INTO " + tableName +
		"(id, session_data, created_on, modified_on, expires_on) VALUES (NULL, ?, ?, ?, ?)"
	stmtInsert, stmtErr := db.Prepare(insQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	delQ := "DELETE FROM " + tableName + " WHERE id = ?"
	stmtDelete, stmtErr := db.Prepare(delQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	updQ := "UPDATE " + tableName + " SET session_data = ?, modified_on = ?, expires_on = ? " +
		"WHERE id = ?"
	stmtUpdate, stmtErr := db.Prepare(updQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	selQ := "SELECT id, session_data, created_on, modified_on, expires_on from " +
		tableName + " WHERE id = ?"
	stmtSelect, stmtErr := db.Prepare(selQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	return &MySQLStore{
		db:         db,
		stmtInsert: stmtInsert,
		stmtDelete: stmtDelete,
		stmtUpdate: stmtUpdate,
		stmtSelect: stmtSelect,
		Codecs:     securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   path,
			MaxAge: maxAge,
		},
		table: tableName,
		Json: false,
	}, nil
}

func (m *MySQLStore) Close() {
	m.stmtSelect.Close()
	m.stmtUpdate.Close()
	m.stmtDelete.Close()
	m.stmtInsert.Close()
	m.db.Close()
}

func (m *MySQLStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

func (m *MySQLStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		Domain:   m.Options.Domain,
		MaxAge:   m.Options.MaxAge,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
		SameSite: m.Options.SameSite,
	}
	session.IsNew = true
	var err error
	if cook, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cook.Value, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			}	
		}
	}
	return session, err
}

func (m *MySQLStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	var err error
	if session.ID == "" {
		if err = m.insert(session); err != nil {
			return err
		}
	} else if err = m.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (m *MySQLStore) insert(session *sessions.Session) error {
	modifiedOn := time.Now()
	expiresOn := modifiedOn.Add(time.Second * time.Duration(session.Options.MaxAge))

	delete(session.Values, "created_on")
	delete(session.Values, "modified_on")
	delete(session.Values, "expires_on")

	var err error
	var marshalled []byte

	sessValues := make(map[string]interface{})
	for k, v := range(session.Values){
		sessValues[fmt.Sprint(k)] = v
	}

	if m.Json {
		marshalled, err = json.Marshal(sessValues)
	}else {
		marshalled, err = (securecookie.GobEncoder{}).Serialize(sessValues)
		encoded := make([]byte, base64.URLEncoding.EncodedLen(len(marshalled)))
		base64.URLEncoding.Encode(encoded, marshalled)
		marshalled = encoded
	}

	if err == nil {
		var res driver.Result
		res, err = m.stmtInsert.Exec(marshalled, modifiedOn, modifiedOn, expiresOn)
		if err == nil {
			var lastInserted int64
			lastInserted, err = res.LastInsertId()
			if err == nil {
				session.ID = fmt.Sprintf("%d", lastInserted)
			}
		}
	}

	if err != nil {
		fmt.Println("Failed to insert session data to database")
		return err
	}
	return nil
}

func (m *MySQLStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {

	// Set cookie to expire.
	options := *session.Options
	options.MaxAge = -1
	http.SetCookie(w, sessions.NewCookie(session.Name(), "", &options))
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}
	_, delErr := m.stmtDelete.Exec(session.ID)
	if delErr != nil {
		return delErr
	}
	return nil
}

func (m *MySQLStore) save(session *sessions.Session) error {
	if session.IsNew == true || session.ID == "" {
		return m.insert(session)
	}
	var expiresOn time.Time

	expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))

	delete(session.Values, "created_on")
	delete(session.Values, "modified_on")
	delete(session.Values, "expires_on")


	var err error
	var marshalled []byte

	sessValues := make(map[string]interface{})
	for k, v := range(session.Values){
		sessValues[fmt.Sprint(k)] = v
	}

	if m.Json { 
		marshalled, err = json.Marshal(sessValues)
	}else{
		marshalled, err = (securecookie.GobEncoder{}).Serialize(sessValues)
		encoded := make([]byte, base64.URLEncoding.EncodedLen(len(marshalled)))
		base64.URLEncoding.Encode(encoded, marshalled)
		marshalled = encoded
	}

	if err == nil {
		_, err = m.stmtUpdate.Exec(marshalled, time.Now(), expiresOn, session.ID)
	}

	if err != nil {
		return err
	}

	return nil
}

func (m *MySQLStore) load(session *sessions.Session) error {
	var err error
	row := m.stmtSelect.QueryRow(session.ID)
	sess := sessionRow{}
	err = row.Scan(&sess.id, &sess.data, &sess.createdOn, &sess.modifiedOn, &sess.expiresOn)

	if err != nil {
		return err
	}

	if sess.expiresOn.Before(time.Now()) {
		return errors.New("Session expired")
	}

	var dataMap map[string]interface{}
	
	if m.Json {
		err = json.Unmarshal(sess.data, &dataMap)
	}

	if !m.Json || err != nil {
		dest := make([]byte, base64.URLEncoding.DecodedLen(len(sess.data)))
		base64.URLEncoding.Decode(dest, sess.data)
		dataMap = make(map[string]interface{}, 0)
		err = (securecookie.GobEncoder{}).Deserialize(dest, &dataMap)
	}

	if err != nil {
		fmt.Printf("Error decoding db session data: %v\n", err)
		dataMap = make(map[string]interface{}, 0)
	}

	session.Values["created_on"] = sess.createdOn
	session.Values["modified_on"] = sess.modifiedOn
	session.Values["expires_on"] = sess.expiresOn

	for k,v := range(dataMap) {
		session.Values[k] = v
	}

	return nil

}
