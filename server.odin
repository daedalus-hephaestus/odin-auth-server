package odin_auth_server

import "core:fmt"
import "core:net"
import "core:encoding/json"
import "core:slice"

import sql "../odin-sql-connect"
import http "../odin-http"
import aes "../odin-tcp-aes"

db : ^sql.Database
Creds :: sql.Creds
SqlCreds :: sql.SqlCreds

serve :: proc(ip: net.IP4_Address, port: int, creds: sql.SqlCreds) {
	s : http.Server
	db = sql.db_connect(creds)

	fmt.printfln("Server listening on %v", port)
	http.server_shutdown_on_interrupt(&s)

	router : http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.route_post(&router, "/auth", http.handler(key))

	route_handler := http.router_handler(&router)

	err := http.listen_and_serve(&s, route_handler, net.Endpoint{
		address = ip,
		port = port
	})
	if err != nil do fmt.printfln("server stopped with %v", err)	

	sql.db_disconnect(db)
}

key :: proc(req: ^http.Request, res: ^http.Response) {
	http.body(req, -1, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
		res := cast(^http.Response)res	
		if err != nil do return

		creds : sql.Creds
		json_err := json.unmarshal_string(body, &creds)
		if json_err != nil {
			fmt.printfln("JSON marshalling error: %v", json_err)
			return
		}
		defer delete(creds.usr)
		defer delete(creds.pwd)

		success := sql.auth_creds(creds, db)

		tag : byte = 1
		key : [32]byte

		if success {
			tag = 0
			key = aes.make_key()
		}
		msg := slice.concatenate([][]byte{ []byte{ tag }, key[:] })
		defer delete(msg)

		http.respond_plain(res, string(msg))

	})
}
