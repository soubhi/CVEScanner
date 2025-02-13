package api

import (
	"github.com/gorilla/mux"
)

func SetupRoutes() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/scan", ScanHandler).Methods("POST")
	r.HandleFunc("/query", QueryHandler).Methods("POST")
	return r
}
