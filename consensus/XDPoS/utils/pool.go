package utils

import (
	"encoding/json"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

type PoolObj interface {
	Hash() common.Hash
	PoolKey() string
	GetSigner() common.Address
}
type Pool struct {
	objList map[string]map[common.Hash]PoolObj
	lock    sync.RWMutex // Protects the pool fields
}

func NewPool() *Pool {
	return &Pool{
		objList: make(map[string]map[common.Hash]PoolObj),
	}
}

func (p *Pool) Get() map[string]map[common.Hash]PoolObj {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.getSnapshot()
}

func (p *Pool) Add(obj PoolObj) (int, map[common.Hash]PoolObj) {
	p.lock.Lock()
	defer p.lock.Unlock()
	poolKey := obj.PoolKey()
	objListKeyed, ok := p.objList[poolKey]
	if !ok {
		p.objList[poolKey] = make(map[common.Hash]PoolObj)
		objListKeyed = p.objList[poolKey]
	}
	objListKeyed[obj.Hash()] = obj
	numOfItems := len(objListKeyed)
	safeCopy := p.getSafePoolObjMap(objListKeyed)
	return numOfItems, safeCopy
}

func (p *Pool) Size(obj PoolObj) int {
	p.lock.Lock()
	defer p.lock.Unlock()
	poolKey := obj.PoolKey()
	objListKeyed, ok := p.objList[poolKey]
	if !ok {
		return 0
	}
	return len(objListKeyed)
}

func (p *Pool) PoolObjKeysList() []string {
	p.lock.RLock()
	defer p.lock.RUnlock()

	var keyList []string
	for key := range p.objList {
		keyList = append(keyList, key)
	}
	return keyList
}

// Given the pool object, clear all object under the same pool key
func (p *Pool) ClearPoolKeyByObj(obj PoolObj) {
	p.lock.Lock()
	defer p.lock.Unlock()

	poolKey := obj.PoolKey()
	delete(p.objList, poolKey)
}

// Given the pool key, clean its content
func (p *Pool) ClearByPoolKey(poolKey string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.objList, poolKey)
}

func (p *Pool) Clear() {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.objList = make(map[string]map[common.Hash]PoolObj)
}

func (p *Pool) GetObjsByKey(poolKey string) []PoolObj {
	p.lock.RLock()
	defer p.lock.RUnlock()

	objListKeyed, ok := p.objList[poolKey]
	if !ok {
		return []PoolObj{}
	}
	objList := make([]PoolObj, len(objListKeyed))
	cnt := 0
	for _, obj := range objListKeyed {
		objList[cnt] = p.getSafePoolObj(obj)
		cnt++
	}
	return objList
}

// caller should hold lock
func (p *Pool) getSnapshot() map[string]map[common.Hash]PoolObj {
	data, err := json.Marshal(p.objList)
	if err != nil {
		// This should never happen
		log.Error("[getSafeCopy] Error while marshalling pool object list", "error", err)
		return make(map[string]map[common.Hash]PoolObj)
	}

	var dataCopy map[string]map[common.Hash]PoolObj
	err = json.Unmarshal(data, &dataCopy)
	if err != nil {
		// This should never happen
		log.Error("[getSafeCopy] Error while unmarshalling pool object list", "error", err)
		return make(map[string]map[common.Hash]PoolObj)
	}

	return dataCopy
}

// caller should hold lock
func (p *Pool) getSafePoolObjMap(objMap map[common.Hash]PoolObj) map[common.Hash]PoolObj {
	data, err := json.Marshal(objMap)
	if err != nil {
		// This should never happen
		log.Error("[getSafeCopy] Error while marshalling pool object list", "error", err)
		return make(map[common.Hash]PoolObj)
	}

	var dataCopy map[common.Hash]PoolObj
	err = json.Unmarshal(data, &dataCopy)
	if err != nil {
		// This should never happen
		log.Error("[getSafeCopy] Error while unmarshalling pool object list", "error", err)
		return make(map[common.Hash]PoolObj)
	}

	return dataCopy
}

// caller should hold lock
func (p *Pool) getSafePoolObj(obj PoolObj) PoolObj {
	data, err := json.Marshal(obj)
	if err != nil {
		// This should never happen
		log.Error("[getSafeCopy] Error while marshalling pool object list", "error", err)
		return nil
	}

	var dataCopy PoolObj
	err = json.Unmarshal(data, &dataCopy)
	if err != nil {
		// This should never happen
		log.Error("[getSafeCopy] Error while unmarshalling pool object list", "error", err)
		return nil
	}

	return dataCopy
}
