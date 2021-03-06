// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	// chainReqCache is an expiring cache for pending requests of certificate chains.
	chainReqCache = NewReqCache(30*time.Second, 10*time.Minute, 1*time.Second)
)

type ChainHandler struct {
	conn *snet.Conn
}

func NewChainHandler(conn *snet.Conn) *ChainHandler {
	return &ChainHandler{conn: conn}
}

// HandleReq handles certificate chain requests. Non-local or cache-only requests are dropped,
// if the certificate chain is not present.
func (h *ChainHandler) HandleReq(addr *snet.Addr, req *cert_mgmt.ChainReq) {
	log.Info("Received certificate chain request", "addr", addr, "req", req)
	chain := store.GetChain(req.IA(), req.Version)
	srcLocal := public.IA.Eq(addr.IA)
	if chain != nil {
		if err := h.sendChainRep(addr, chain); err != nil {
			log.Error("Unable to send certificate chain reply", "addr", addr, "req",
				req, "err", err)
		}
	} else if !srcLocal || req.CacheOnly {
		log.Info("Dropping certificate chain request", "addr", addr, "req", req, "err",
			"certificate chain not found")
	} else {
		if err := h.fetchChain(addr, req); err != nil {
			log.Error("Unable to fetch certificate chain", "req", req, "err", err)
		}
	}
}

// sendChainRep creates a certificate chain response and sends it to the requester.
func (h *ChainHandler) sendChainRep(addr *snet.Addr, chain *cert.Chain) error {
	raw, err := chain.Compress()
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.ChainRep{RawChain: raw})
	if err != nil {
		return err
	}
	log.Debug("Send certificate chain reply", "chain", chain, "addr", addr)
	return SendPayload(h.conn, cpld, addr)
}

// fetchChain fetches certificate chain from the remote AS.
func (h *ChainHandler) fetchChain(addr *snet.Addr, req *cert_mgmt.ChainReq) error {
	key := cert.NewKey(req.IA(), req.Version).String()
	sendReq := chainReqCache.Put(key, addr)
	if sendReq { // rate limit
		return h.sendChainReq(req)
	}
	log.Info("Ignoring certificate chain request (same request already pending)",
		"addr", addr, "req", req)
	return nil
}

// sendChainReq sends a certificate chain request to the specified remote AS.
func (h *ChainHandler) sendChainReq(req *cert_mgmt.ChainReq) error {
	cpld, err := ctrl.NewCertMgmtPld(req)
	if err != nil {
		return err
	}
	a := &snet.Addr{IA: req.IA(), Host: addr.SvcCS}
	log.Debug("Send certificate chain request", "req", req, "addr", a)
	return SendPayload(h.conn, cpld, a)
}

// HandleChainRep handles certificate chain replies. Pending requests are answered and removed.
func (h *ChainHandler) HandleRep(addr *snet.Addr, rep *cert_mgmt.ChainRep) {
	log.Info("Received certificate chain reply", "addr", addr, "rep", rep)
	chain, err := rep.Chain()
	if err != nil {
		log.Error("Unable to parse certificate reply", "err", err)
	}
	if err = store.AddChain(chain, true); err != nil {
		log.Error("Unable to store certificate chain", "key", chain.Key(), "err", err)
		return
	}
	reqs := chainReqCache.Pop(chain.Key().String())
	if reqs == nil { // No pending requests
		return
	}
	cpld, err := ctrl.NewCertMgmtPld(rep)
	if err != nil {
		log.Error("Unable to create certificate chain reply", "key", chain.Key(),
			"err", err)
		return
	}
	for _, dst := range reqs.Addrs {
		if err := SendPayload(h.conn, cpld, dst); err != nil {
			log.Error("Unable to write certificate chain reply", "key", chain.Key(),
				"err", err)
			continue
		}
	}
}
