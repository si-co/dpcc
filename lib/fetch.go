package lib

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/PuerkitoBio/goquery"
	"go.dedis.ch/onet/v3/log"
)

// Resource is used to store everything is needed about the resource to run the
// protocol
type Resource struct {
	URL         string
	ContentType string
	Data        []byte
}

// FetchMainResource fetches the resource referenced by URL and return it as a
// format-agnostic array of bytes, together with the content type. Note that
// this function only fetches the main content referenced by the URL and not
// other contents present in the resource.
func FetchMainResource(URL string) (*Resource, error) {
	// parse the URL to see if there is any problem
	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}

	// we handle the request depending on the scheme specified in the url
	var res *http.Response
	switch u.Scheme {
	case "http", "https":
		res, err = http.Get(u.String())
		if err != nil {
			return nil, err
		}
		if res.StatusCode != 200 {
			s := strconv.Itoa(res.StatusCode)
			return nil, errors.New("status code " + s + " different from 200, aborting")
		}
		defer res.Body.Close()
	case "file":
		// this can be very dangerous, because we give the client access
		// to the conodes file. We allow to use file as scheme only for
		// research purposes

		// The typical use case for NewFileTransport is to register the
		// "file" protocol with a Transport.
		t := &http.Transport{}
		// we want to access only the upper folder and nothing else
		t.RegisterProtocol("file", http.NewFileTransport(http.Dir("..")))
		c := &http.Client{Transport: t}
		res, err = c.Get(u.String())
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
	default:
		return nil, errors.New("scheme not supported")

	}

	// from now on the procedure is the same for http, https, and file:///

	// get data
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	// get content type
	ct := res.Header.Get("Content-Type")

	// test if content type is supported: for now we handle
	// text/html, text/css, and image/*
	re := regexp.MustCompile(`html|image|css`)
	if !re.MatchString(ct) {
		return nil, errors.New("unsupported content type: " + ct)
	}

	r := &Resource{
		URL:         URL,
		ContentType: ct,
		Data:        b,
	}

	return r, nil
}

// FetchAllResources fetches the main content and (part of) the files
// referenced in it
func FetchAllResources(URL string) ([]*Resource, error) {
	resources := make([]*Resource, 0)

	// get main page
	mainResource, err := FetchMainResource(URL)
	if err != nil {
		return nil, err
	}

	resources = append(resources, mainResource)

	// get link from main page
	// the function scrapeLinks defines the additional resources downloaded
	links := scrapeLinks(URL, bytes.NewBuffer(resources[0].Data))

	// get additional resources
	for _, l := range links {
		r, err := FetchMainResource(l)
		if err == nil {
			resources = append(resources, r)
		}
	}

	return resources, nil
}

// scrapeLinks returns a list of strings extracted from the page referenced by
// pageURL
func scrapeLinks(pageURL string, page *bytes.Buffer) []string {
	// load page
	doc, err := goquery.NewDocumentFromReader(page)
	if err != nil {
		log.Fatal(err)
	}

	links := make([]string, 0)

	// get CSS files
	doc.Find("link[rel='stylesheet']").Each(func(index int, item *goquery.Selection) {
		href, _ := item.Attr("href")
		l, err := sanitizeLink(pageURL, href)
		if err == nil { // if error, just skip this link
			links = append(links, l)
		}

	})

	// get images files
	doc.Find("img").Each(func(indec int, item *goquery.Selection) {
		src, _ := item.Attr("src")
		l, err := sanitizeLink(pageURL, src)
		if err == nil { // if error, just skip this link
			links = append(links, l)
		}
	})

	return links
}

func sanitizeLink(pageURL, link string) (string, error) {
	l, err := url.Parse(link)
	if err != nil {
		return "", err
	}

	// if link to resource is absolute, we can return
	if l.IsAbs() {
		return l.String(), nil
	}

	// o/w we have to add the page url
	u, err := url.Parse(pageURL)
	if err != nil {
		return "", err
	}
	l, err = u.Parse(link)
	if err != nil {
		return "", err
	}
	return l.String(), nil
}
