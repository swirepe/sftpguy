package adminhttp

import (
	"net/http"

	"github.com/arl/statsviz"
)

func RegisterStatsViz(mux *http.ServeMux, cfg Config) error {
	// return statsviz.Register(mux,
	// 	statsviz.Root("/admin/stats"),
	// 	statsviz.SendFrequency(250*time.Millisecond),
	// )

	srv, err := statsviz.NewServer()
	if err != nil {
		return err
	}

	register(mux, "/admin/stats", cfg, srv.Index())
	register(mux, "/admin/stats/ws", cfg, srv.Ws())
	// mux.Handle("/debug/statsviz/", basicAuth(srv.Index(), "statsviz", "rocks", ""))
	// mux.HandleFunc("/debug/statsviz/ws", srv.Ws())

	// fmt.Println("Point your browser to http://localhost:8090/debug/statsviz/")
	// fmt.Println("Basic auth user:     statsviz")
	// fmt.Println("Basic auth password: rocks")
	// log.Fatal(http.ListenAndServe(":8090", mux))
	return nil
}
