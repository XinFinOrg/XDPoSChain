// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package dnsdisc

import (
	"context"
	"crypto/ecdsa"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/internal/testlog"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
	"github.com/XinFinOrg/XDPoSChain/p2p/enr"
	"github.com/davecgh/go-spew/spew"
)

const (
	signingKeySeed = 0x111111
	nodesSeed1     = 0x2945237
	nodesSeed2     = 0x4567299
)

var testTreeSigningKey = testKey(signingKeySeed)

func TestClientSyncTree(t *testing.T) {
	nodes := []string{
		"enr:-HW4QOFzoVLaFJnNhbgMoDXPnOvcdVuj7pDpqRvh6BRDO68aVi5ZcjB3vzQRZH2IcLBGHzo8uUN3snqmgTiE56CH3AMBgmlkgnY0iXNlY3AyNTZrMaECC2_24YYkYHEgdzxlSNKQEnHhuNAbNlMlWJxrJxbAFvA",
		"enr:-HW4QAggRauloj2SDLtIHN1XBkvhFZ1vtf1raYQp9TBW2RD5EEawDzbtSmlXUfnaHcvwOizhVYLtr7e6vw7NAf6mTuoCgmlkgnY0iXNlY3AyNTZrMaECjrXI8TLNXU0f8cthpAMxEshUyQlK-AM0PW2wfrnacNI",
		"enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o",
	}
	r := mapResolver{
		"n":                            "enrtree-root:v1 e=JWXYDBPXYWG6FX3GMDIBFA6CJ4 l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=1 sig=o908WmNp7LibOfPsr4btQwatZJ5URBr2ZAuxvK4UWHlsB9sUOTJQaGAlLPVAhM__XJesCHxLISo94z5Z2a463gA",
		"C7HRFPF3BLGF3YR4DY5KX3SMBE.n": "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org",
		"JWXYDBPXYWG6FX3GMDIBFA6CJ4.n": "enrtree-branch:2XS2367YHAXJFGLZHVAWLQD4ZY,H4FHT4B454P6UXFD7JCYQ5PWDY,MHTDO6TMUBRIA2XWG5LUDACK24",
		"2XS2367YHAXJFGLZHVAWLQD4ZY.n": "enr:-HW4QOFzoVLaFJnNhbgMoDXPnOvcdVuj7pDpqRvh6BRDO68aVi5ZcjB3vzQRZH2IcLBGHzo8uUN3snqmgTiE56CH3AMBgmlkgnY0iXNlY3AyNTZrMaECC2_24YYkYHEgdzxlSNKQEnHhuNAbNlMlWJxrJxbAFvA",
		"H4FHT4B454P6UXFD7JCYQ5PWDY.n": "enr:-HW4QAggRauloj2SDLtIHN1XBkvhFZ1vtf1raYQp9TBW2RD5EEawDzbtSmlXUfnaHcvwOizhVYLtr7e6vw7NAf6mTuoCgmlkgnY0iXNlY3AyNTZrMaECjrXI8TLNXU0f8cthpAMxEshUyQlK-AM0PW2wfrnacNI",
		"MHTDO6TMUBRIA2XWG5LUDACK24.n": "enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o",
	}
	var (
		wantNodes = sortByID(parseNodes(t, nodes))
		wantLinks = []string{"enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org"}
		wantSeq   = uint(1)
	)

	c := NewClient(Config{Resolver: r, Logger: testlog.Logger(t, log.LvlTrace)})
	stree, err := c.SyncTree("enrtree://AKPYQIUQIL7PSIACI32J7FGZW56E5FKHEFCCOFHILBIMW3M6LWXS2@n")
	if err != nil {
		t.Fatal("sync error:", err)
	}
	if !reflect.DeepEqual(sortByID(stree.Nodes()), sortByID(wantNodes)) {
		t.Errorf("wrong nodes in synced tree:\nhave %v\nwant %v", spew.Sdump(stree.Nodes()), spew.Sdump(wantNodes))
	}
	if !reflect.DeepEqual(stree.Links(), wantLinks) {
		t.Errorf("wrong links in synced tree: %v", stree.Links())
	}
	if stree.Seq() != wantSeq {
		t.Errorf("synced tree has wrong seq: %d", stree.Seq())
	}
}

// In this test, syncing the tree fails because it contains an invalid ENR entry.
func TestClientSyncTreeBadNode(t *testing.T) {
	r := mapResolver{
		"n":                            "enrtree-root:v1 e=INDMVBZEEQ4ESVYAKGIYU74EAA l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=3 sig=Vl3AmunLur0JZ3sIyJPSH6A3Vvdp4F40jWQeCmkIhmcgwE4VC5U9wpK8C_uL_CMY29fd6FAhspRvq2z_VysTLAA",
		"C7HRFPF3BLGF3YR4DY5KX3SMBE.n": "enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org",
		"INDMVBZEEQ4ESVYAKGIYU74EAA.n": "enr:-----",
	}
	c := NewClient(Config{Resolver: r, Logger: testlog.Logger(t, log.LvlTrace)})
	_, err := c.SyncTree("enrtree://AKPYQIUQIL7PSIACI32J7FGZW56E5FKHEFCCOFHILBIMW3M6LWXS2@n")
	wantErr := nameError{name: "INDMVBZEEQ4ESVYAKGIYU74EAA.n", err: entryError{typ: "enr", err: errInvalidENR}}
	if err != wantErr {
		t.Fatalf("expected sync error %q, got %q", wantErr, err)
	}
}

// This test checks that randomIterator finds all entries.
func TestIterator(t *testing.T) {
	nodes := testNodes(nodesSeed1, 30)
	tree, url := makeTestTree("n", nodes, nil)
	r := mapResolver(tree.ToTXT("n"))
	c := NewClient(Config{
		Resolver:  r,
		Logger:    testlog.Logger(t, log.LvlTrace),
		RateLimit: 500,
	})
	it, err := c.NewIterator(url)
	if err != nil {
		t.Fatal(err)
	}

	checkIterator(t, it, nodes)
}

// This test checks if closing randomIterator races.
func TestIteratorClose(t *testing.T) {
	nodes := testNodes(nodesSeed1, 500)
	tree1, url1 := makeTestTree("t1", nodes, nil)
	c := NewClient(Config{Resolver: newMapResolver(tree1.ToTXT("t1"))})
	it, err := c.NewIterator(url1)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for it.Next() {
			_ = it.Node()
		}
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	it.Close()
	<-done
}

// This test checks that randomIterator traverses linked trees as well as explicitly added trees.
func TestIteratorLinks(t *testing.T) {
	nodes := testNodes(nodesSeed1, 40)
	tree1, url1 := makeTestTree("t1", nodes[:10], nil)
	tree2, url2 := makeTestTree("t2", nodes[10:], []string{url1})
	c := NewClient(Config{
		Resolver:  newMapResolver(tree1.ToTXT("t1"), tree2.ToTXT("t2")),
		Logger:    testlog.Logger(t, log.LvlTrace),
		RateLimit: 500,
	})
	it, err := c.NewIterator(url2)
	if err != nil {
		t.Fatal(err)
	}

	checkIterator(t, it, nodes)
}

// This test verifies that randomIterator re-checks the root of the tree to catch
// updates to nodes.
func TestIteratorNodeUpdates(t *testing.T) {
	var (
		nodes    = testNodes(nodesSeed1, 30)
		resolver = newMapResolver()
		c        = NewClient(Config{
			Resolver:  resolver,
			Logger:    testlog.Logger(t, log.LevelError),
			RateLimit: 500,
		})
	)
	tree1, url := makeTestTree("n", nodes[:25], nil)
	resolver.add(tree1.ToTXT("n"))
	resolver["n"] = tree1.root.String()
	loc, err := parseLink(url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAndVerifyRoot(resolver["n"], loc); err != nil {
		t.Fatalf("initial root/url mismatch: %q (%v)", resolver["n"], err)
	}
	stree1, err := c.SyncTree(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(stree1.Nodes()) != 25 {
		t.Fatalf("initial tree node count mismatch, have %d want 25", len(stree1.Nodes()))
	}

	// Update some nodes and ensure RandomNode returns the new nodes as well.
	keys := testKeys(nodesSeed1, len(nodes))
	for i, n := range nodes[:len(nodes)/2] {
		r := n.Record()
		r.Set(enr.IP{127, 0, 0, 1})
		r.SetSeq(55)
		enode.SignV4(r, keys[i])
		n2, _ := enode.New(enode.ValidSchemes, r)
		nodes[i] = n2
	}
	tree2, _ := makeTestTree("n", nodes, nil)
	resolver.clear()
	resolver.add(tree2.ToTXT("n"))
	resolver["n"] = tree2.root.String()
	if _, err := parseAndVerifyRoot(resolver["n"], loc); err != nil {
		t.Fatalf("updated root/url mismatch: %q (%v)", resolver["n"], err)
	}
	c.entries.Purge()
	stree2, err := c.SyncTree(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(stree2.Nodes()) != len(nodes) {
		t.Fatalf("updated tree node count mismatch, have %d want %d", len(stree2.Nodes()), len(nodes))
	}
	updated := 0
	for _, n := range stree2.Nodes() {
		if n.Record().Seq() == 55 {
			updated++
		}
	}
	if updated < len(nodes)/2 {
		t.Fatalf("updated nodes not visible after refresh, have %d want at least %d", updated, len(nodes)/2)
	}
}

// This test verifies that randomIterator re-checks the root of the tree to catch
// updates to links.
func TestIteratorLinkUpdates(t *testing.T) {
	var (
		nodes    = testNodes(nodesSeed1, 30)
		resolver = newMapResolver()
		c        = NewClient(Config{
			Resolver:  resolver,
			Logger:    testlog.Logger(t, log.LevelError),
			RateLimit: 500,
		})
	)
	tree3, url3 := makeTestTree("t3", nodes[20:30], nil)
	tree2, url2 := makeTestTree("t2", nodes[10:20], nil)
	tree1, url1 := makeTestTree("t1", nodes[0:10], []string{url2})
	resolver.add(tree1.ToTXT("t1"))
	resolver.add(tree2.ToTXT("t2"))
	resolver.add(tree3.ToTXT("t3"))
	resolver["t1"] = tree1.root.String()
	resolver["t2"] = tree2.root.String()
	resolver["t3"] = tree3.root.String()
	loc1, err := parseLink(url1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAndVerifyRoot(resolver["t1"], loc1); err != nil {
		t.Fatalf("initial tree1 root/url mismatch: %q (%v)", resolver["t1"], err)
	}

	before, err := c.SyncTree(url1)
	if err != nil {
		t.Fatal(err)
	}
	beforeLinks := before.Links()
	if len(beforeLinks) != 1 || beforeLinks[0] != url2 {
		t.Fatalf("initial tree links mismatch, have %v want [%s]", beforeLinks, url2)
	}

	// Add link to tree3, remove link to tree2.
	tree1, _ = makeTestTree("t1", nodes[:10], []string{url3})
	resolver.clear()
	resolver.add(tree1.ToTXT("t1"))
	resolver.add(tree2.ToTXT("t2"))
	resolver.add(tree3.ToTXT("t3"))
	resolver["t1"] = tree1.root.String()
	resolver["t2"] = tree2.root.String()
	resolver["t3"] = tree3.root.String()
	if _, err := parseAndVerifyRoot(resolver["t1"], loc1); err != nil {
		t.Fatalf("updated tree1 root/url mismatch: %q (%v)", resolver["t1"], err)
	}
	c.entries.Purge()
	t.Log("tree1 updated")
	stree, err := c.SyncTree(url1)
	if err != nil {
		t.Fatal(err)
	}
	links := stree.Links()
	if len(links) != 1 || links[0] != url3 {
		t.Fatalf("updated tree links mismatch, have %v want [%s]", links, url3)
	}
}

func checkIterator(t *testing.T, it enode.Iterator, wantNodes []*enode.Node) {
	t.Helper()

	var (
		want     = make(map[enode.ID]*enode.Node)
		maxCalls = len(wantNodes) * 3
		calls    = 0
	)
	for _, n := range wantNodes {
		want[n.ID()] = n
	}
	for ; len(want) > 0 && calls < maxCalls; calls++ {
		if !it.Next() {
			t.Fatalf("Next returned false (call %d)", calls)
		}
		n := it.Node()
		delete(want, n.ID())
	}
	t.Logf("checkIterator called Next %d times to find %d nodes", calls, len(wantNodes))
	for _, n := range want {
		t.Errorf("iterator didn't discover node %v", n.ID())
	}
}

func makeTestTree(domain string, nodes []*enode.Node, links []string) (*Tree, string) {
	tree, err := MakeTree(1, nodes, links)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 10; i++ {
		url, err := tree.Sign(testTreeSigningKey, domain)
		if err != nil {
			panic(err)
		}
		loc, err := parseLink(url)
		if err != nil {
			panic(err)
		}
		if _, err := parseAndVerifyRoot(tree.root.String(), loc); err == nil {
			return tree, url
		}
	}
	panic("could not create verifiable test tree root")
}

// testKeys creates deterministic private keys for testing.
func testKeys(seed int64, n int) []*ecdsa.PrivateKey {
	rand := rand.New(rand.NewSource(seed))
	keys := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		key, err := ecdsa.GenerateKey(crypto.S256(), rand)
		if err != nil {
			panic("can't generate key: " + err.Error())
		}
		keys[i] = key
	}
	return keys
}

func testKey(seed int64) *ecdsa.PrivateKey {
	return testKeys(seed, 1)[0]
}

func testNodes(seed int64, n int) []*enode.Node {
	keys := testKeys(seed, n)
	nodes := make([]*enode.Node, n)
	for i, key := range keys {
		record := new(enr.Record)
		record.SetSeq(uint64(i))
		enode.SignV4(record, key)
		n, err := enode.New(enode.ValidSchemes, record)
		if err != nil {
			panic(err)
		}
		nodes[i] = n
	}
	return nodes
}

func parseNodes(t *testing.T, records []string) []*enode.Node {
	t.Helper()

	nodes := make([]*enode.Node, len(records))
	for i, record := range records {
		n, err := parseNode(record, enode.ValidSchemes)
		if err != nil {
			t.Fatalf("invalid test node %d: %v", i, err)
		}
		nodes[i] = n
	}
	return nodes
}

func parseNode(record string, validSchemes enr.IdentityScheme) (*enode.Node, error) {
	return enode.Parse(validSchemes, record)
}

func testNode(seed int64) *enode.Node {
	return testNodes(seed, 1)[0]
}

type mapResolver map[string]string

func newMapResolver(maps ...map[string]string) mapResolver {
	mr := make(mapResolver)
	for _, m := range maps {
		mr.add(m)
	}
	return mr
}

func (mr mapResolver) clear() {
	for k := range mr {
		delete(mr, k)
	}
}

func (mr mapResolver) add(m map[string]string) {
	for k, v := range m {
		mr[k] = v
	}
}

func (mr mapResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if record, ok := mr[name]; ok {
		return []string{record}, nil
	}
	return nil, nil
}
