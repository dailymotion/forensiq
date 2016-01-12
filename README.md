# Forensiq

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/dailymotion/forensiq) [![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/dailymotion/forensiq/master/LICENSE) [![Build Status](https://travis-ci.org/dailymotion/forensiq.svg?branch=master)](https://travis-ci.org/dailymotion/forensiq) [![Coverage](http://gocover.io/_badge/github.com/dailymotion/forensiq)](http://gocover.io/github.com/dailymotion/forensiq)

Forensiq is a Go library interfacing [Forensiq](http://forensiq.com/)
API.

## Installing

    go get -u github.com/dailymotion/forensiq

## Usage

```Go
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/dailymotion/forensiq"
	"github.com/rs/xlog"
	"golang.org/x/net/context"
)

func main() {
	// create the context and a logger to it.
	ctx := context.Background()
	ctx = xlog.NewContext(ctx, xlog.New(xlog.Config{Output: xlog.NewConsoleOutput()}))

	// create a new forensiq object.
	fq := forensiq.New("http://api.forensiq.com", "xxx") // Replace xxx with your client key.

	// create a Forensiq Request.
	fqreq := forensiq.CheckRequest{
		IP:          net.ParseIP("8.8.8.8"),
		RequestType: "display",
		URL:         "http://www.dailymotion.com/video/x3llhsx_ces-2016-wired-s-favorite-gadgets-of-ces_tech",
		SellerID:    "123",
		SubID:       "78679676",
		Campaign:    "217673313",
		UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36",
		CookieID:    "2acc8d3b1a08cf1dd19185d809d04737",
	}

	// give the request one second to complete
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	// send the request to forensiq, the response is of type forensiq.CheckResponse
	fqresp, err := fq.Check(ctx, fqreq)
	if err != nil {
		log.Fatalf("error with the request to Forensiq: %s", err)
	}

	fmt.Printf("%#v", fqresp)
}
```

Running this should return the following:

```
forensiq.CheckResponse{RiskScore:0, SellerDomain:0, DomainViewed:0, DomainHidden:0, SellerViewed:0, SellerHidden:0, IPReputation:false, Proxy:false, AutomatedTraffic:false, HostingProvider:false, Spoofed:0, NonSuspect:true, TimeMS:2}
```

## Licenses

All source code is licensed under the [MIT License](https://raw.github.com/dailymotion/forensiq/master/LICENSE).
