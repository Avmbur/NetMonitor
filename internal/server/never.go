package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/netipx"
	"netmonitor/internal/store"
)

type uiNever struct {
	ID     string `json:"id"`
	Addr   string `json:"addr"`
	Note   string `json:"note"`
	Locked bool   `json:"locked"`
}

var errNeverMissing = errors.New("запись не найдена")
var errNeverDuplicate = errors.New("такой адрес уже есть")

func canonicalPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("укажи IP или CIDR")
	}
	return p.Masked(), nil
}
func saveNever(st *store.Store, id, addr, note, actor string) (string, error) {
	if id == "monitor" {
		return "", fmt.Errorf("адрес монитора защищён")
	}
	p, err := canonicalPrefix(addr)
	if err != nil {
		return "", err
	}
	isNew := id == ""
	if isNew {
		id = idgen.NewV7()
	}
	lo, hi := netipx.PrefixBinRange(p)
	err = st.Update(func(tx *sql.Tx) error {
		var other string
		err := tx.QueryRow("SELECT id FROM never_block WHERE cidr=? AND id!=?", p.String(), id).Scan(&other)
		if err == nil {
			return errNeverDuplicate
		}
		if err != sql.ErrNoRows {
			return err
		}
		if isNew {
			_, err = tx.Exec("INSERT INTO never_block(id,cidr,ip_lo_bin,ip_hi_bin,reason,created_at_ms) VALUES(?,?,?,?,?,?)", id, p.String(), lo, hi, note, store.NowMS())
		} else {
			var res sql.Result
			res, err = tx.Exec("UPDATE never_block SET cidr=?,ip_lo_bin=?,ip_hi_bin=?,reason=? WHERE id=?", p.String(), lo, hi, note, id)
			if err == nil {
				var n int64
				n, err = res.RowsAffected()
				if err == nil && n != 1 {
					return errNeverMissing
				}
			}
		}
		if err != nil {
			return err
		}
		if err = bumpTrusted(tx); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), actor, "сохранил не блокировать", p.String())
		return err
	})
	return id, err
}
func deleteNever(st *store.Store, id string) error {
	if id == "" || id == "monitor" {
		return fmt.Errorf("адрес монитора защищён")
	}
	return st.Update(func(tx *sql.Tx) error {
		var addr string
		if err := tx.QueryRow("SELECT cidr FROM never_block WHERE id=?", id).Scan(&addr); err != nil {
			if err == sql.ErrNoRows {
				return errNeverMissing
			}
			return err
		}
		if _, err := tx.Exec("DELETE FROM never_block WHERE id=?", id); err != nil {
			return err
		}
		if err := bumpTrusted(tx); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), "adm", "удалил не блокировать", addr)
		return err
	})
}
func (s *Server) handleNever(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		id := r.PathValue("id")
		if id == "monitor" {
			http.Error(w, "адрес монитора защищён", http.StatusForbidden)
			return
		}
		err := deleteNever(s.st, id)
		if err != nil {
			code := 500
			if errors.Is(err, errNeverMissing) {
				code = 404
			}
			http.Error(w, err.Error(), code)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	var in struct {
		ID   string `json:"id"`
		Addr string `json:"addr"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		http.Error(w, "неверный запрос", 400)
		return
	}
	if in.ID == "monitor" {
		http.Error(w, "адрес монитора защищён", 403)
		return
	}
	if _, err := canonicalPrefix(in.Addr); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id, err := saveNever(s.st, in.ID, in.Addr, in.Note, "adm")
	if err != nil {
		code := 500
		if errors.Is(err, errNeverDuplicate) {
			code = 409
		}
		if errors.Is(err, errNeverMissing) {
			code = 404
		}
		http.Error(w, err.Error(), code)
		return
	}
	writeJSON(w, map[string]string{"id": id})
}
