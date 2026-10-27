// Package wucatalog turns the package.xml inside Microsoft's wsusscn2.cab into
// "which files install this update": for every UpdateID a device can report as
// missing, the Microsoft download URL and SHA-1 of its installable payload.
//
// package.xml (OfflineSyncPackage) layout, as seen in the 2026-10 cab:
//
//	<Update UpdateId=.. RevisionId=.. IsBundle="true">          the bundle a device reports
//	<Update UpdateId=.. RevisionId=..>
//	    <PayloadFiles><File Id="<b64 sha1>"/>..</PayloadFiles>  the files
//	    <BundledBy><Revision Id="<bundle's RevisionId>"/></BundledBy>
//	<FileLocations><FileLocation Id="<b64 sha1>" Url=".."/>
//
// so a bundle's files are its own payload plus its children's (children name
// their bundle by RevisionId). Titles and KB numbers are not in package.xml;
// the KB comes from the device's scan report.
package wucatalog

import (
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type File struct {
	Digest string // base64 SHA-1
	Name   string
	URL    string
}

type update struct {
	id        string
	bundledBy []int
	payload   []string
}

// Parse reads package.xml and returns installable files per UpdateID
// (lowercase). Updates without installable files are omitted.
func Parse(r io.Reader) (map[string][]File, error) {
	dec := xml.NewDecoder(r)
	var updates []*update
	revToID := map[int]string{}
	locations := map[string]string{} // digest -> url

	var cur *update
	var section string // direct child of the current <Update> we're inside
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse package.xml: %w", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case e.Name.Local == "Update" && depth == 3: // OfflineSyncPackage/Updates/Update
				cur = &update{id: strings.ToLower(attr(e, "UpdateId"))}
				if rev, err := strconv.Atoi(attr(e, "RevisionId")); err == nil {
					revToID[rev] = cur.id
				}
				updates = append(updates, cur)
			case cur != nil && depth == 4:
				section = e.Name.Local
			case cur != nil && depth == 5 && section == "PayloadFiles" && e.Name.Local == "File":
				cur.payload = append(cur.payload, attr(e, "Id"))
			case cur != nil && depth == 5 && section == "BundledBy" && e.Name.Local == "Revision":
				if rev, err := strconv.Atoi(attr(e, "Id")); err == nil {
					cur.bundledBy = append(cur.bundledBy, rev)
				}
			case e.Name.Local == "FileLocation":
				locations[attr(e, "Id")] = attr(e, "Url")
			}
		case xml.EndElement:
			if depth == 3 && e.Name.Local == "Update" {
				cur = nil
			}
			if depth == 4 {
				section = ""
			}
			depth--
		}
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("parse package.xml: no updates found")
	}

	files := map[string]map[string]File{} // update id -> digest -> file
	add := func(id string, f File) {
		if files[id] == nil {
			files[id] = map[string]File{}
		}
		files[id][f.Digest] = f
	}
	for _, u := range updates {
		for _, digest := range u.payload {
			url := locations[digest]
			if url == "" {
				continue
			}
			name := path.Base(url)
			if !installable(name) {
				continue
			}
			f := File{Digest: digest, Name: name, URL: url}
			add(u.id, f)
			for _, rev := range u.bundledBy {
				if parent, ok := revToID[rev]; ok {
					add(parent, f)
				}
			}
		}
	}

	out := make(map[string][]File, len(files))
	for id, set := range files {
		list := make([]File, 0, len(set))
		for _, f := range set {
			list = append(list, f)
		}
		out[id] = preferMSU(list)
	}
	return out, nil
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

var kbInName = regexp.MustCompile(`kb\d{6,8}`)

// installable keeps the files DISM installs (.msu / .cab carrying a KB number)
// and drops the Windows Update-only delivery artifacts that ride in the same
// bundles: express/baseless deltas, .psf payloads, .wim feature images,
// metadata cabs.
func installable(name string) bool {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".msu") && !strings.HasSuffix(n, ".cab") {
		return false
	}
	if strings.Contains(n, "express") || strings.Contains(n, "baseless") {
		return false
	}
	return kbInName.MatchString(n)
}

// preferMSU: when a bundle ships .msu files, those are the complete packages
// (a 24H2 cumulative ships its .msu plus the checkpoint .msu it needs) and any
// KB .cab next to them is a WU-internal piece; otherwise (older updates) the
// .cab is the package. Sorted by name for stable output.
func preferMSU(list []File) []File {
	var msu []File
	for _, f := range list {
		if strings.HasSuffix(strings.ToLower(f.Name), ".msu") {
			msu = append(msu, f)
		}
	}
	if len(msu) > 0 {
		list = msu
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// KBOf returns the KB number ("5066835") in a file name, or "".
func KBOf(name string) string {
	m := kbInName.FindString(strings.ToLower(name))
	return strings.TrimPrefix(m, "kb")
}
