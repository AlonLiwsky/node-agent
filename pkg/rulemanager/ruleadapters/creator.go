package ruleadapters

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/dustin/go-humanize"
	"github.com/goradd/maps"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"golang.org/x/sync/singleflight"
)

const (
	maxFileSize      = 50 * 1024 * 1024 // 50MB
	hashCacheTTL     = 30 * time.Minute
	hashCacheMaxSize = 50000

	// racyWindow is how recent a file's ctime may be, relative to the moment it is
	// hashed, before the hash is not cached. The kernel stamps mtime and ctime
	// from a coarse clock, so a rewrite of the same size within the same tick as
	// the previous change leaves the identity unchanged. Such a file is hashed
	// again on the next alert instead.
	racyWindow = 2500 * time.Millisecond
)

var ErrRuleShouldNotBeAlerted = errors.New("rule should not be alerted")

var errFileChanged = errors.New("file changed while it was being hashed")

type FileHashCache struct {
	SHA1Hash string
	MD5Hash  string
}

// hashKey identifies one file in one container. Each overlay mount has its own
// st_dev, so the identity already tells containers apart; the container ID is
// defence in depth, because anonymous device numbers are reused after a
// container exits.
type hashKey struct {
	containerID string
	file        utils.FileIdentity
}

type RuleFailureCreator struct {
	adapterFactory   *EventRuleAdapterFactory
	containerIdToPid *maps.SafeMap[string, uint32]
	dnsManager       dnsmanager.DNSResolver
	enricher         types.Enricher
	hashCache        *expirable.LRU[hashKey, *FileHashCache]
	hashGroup        singleflight.Group
	racyWindow       time.Duration
	calculateHashes  func(io.Reader) (sha1Hash, md5Hash string, err error)
	alertPlatform    armotypes.AlertSourcePlatform
	agentVersion     string
}

func NewRuleFailureCreator(enricher types.Enricher, dnsManager dnsmanager.DNSResolver, adapterFactory *EventRuleAdapterFactory, alertPlatform armotypes.AlertSourcePlatform, agentVersion string, containerIdToPid *maps.SafeMap[string, uint32]) *RuleFailureCreator {
	hashCache := expirable.NewLRU[hashKey, *FileHashCache](hashCacheMaxSize, nil, hashCacheTTL)
	return &RuleFailureCreator{
		adapterFactory:   adapterFactory,
		containerIdToPid: containerIdToPid,
		dnsManager:       dnsManager,
		enricher:         enricher,
		hashCache:        hashCache,
		calculateHashes:  utils.CalculateHashes,
		racyWindow:       racyWindow,
		alertPlatform:    alertPlatform,
		agentVersion:     agentVersion,
	}
}

func (r *RuleFailureCreator) CreateRuleFailure(rule typesv1.Rule, enrichedEvent *events.EnrichedEvent, objectCache objectcache.ObjectCache, message, uniqueID, apChecksum string, state map[string]any) types.RuleFailure {
	eventAdapter, ok := r.adapterFactory.GetAdapter(enrichedEvent.Event.GetEventType())
	if !ok {
		logger.L().Error("RuleFailureCreator - no adapter registered for event type", helpers.String("eventType", string(enrichedEvent.Event.GetEventType())))
		return nil
	}

	ruleFailure := &types.GenericRuleFailure{
		BaseRuntimeAlert: armotypes.BaseRuntimeAlert{
			UniqueID:  uniqueID,
			AlertName: rule.Name,
			Severity:  rule.Severity,
			Arguments: map[string]any{
				"apChecksum": apChecksum,
				"message":    message,
			},
			Timestamp:    enrichedEvent.Timestamp,
			InfectedPID:  enrichedEvent.ProcessTree.PID,
			AgentVersion: r.agentVersion,
		},
		RuleAlert: armotypes.RuleAlert{
			RuleDescription: message,
		},
		RuleID:         rule.ID,
		AlertPlatform:  r.alertPlatform,
		IsTriggerAlert: rule.IsTriggerAlert,
	}

	eventAdapter.SetFailureMetadata(ruleFailure, enrichedEvent, state)

	r.setBaseRuntimeAlert(ruleFailure)
	r.setRuntimeAlertK8sDetails(ruleFailure, objectCache)
	r.setCloudServices(ruleFailure)
	r.setProfileMetadata(rule, ruleFailure, objectCache)
	r.setContextSpecificFields(ruleFailure, enrichedEvent)
	r.enrichRuleFailure(ruleFailure)

	if enrichedEvent.ProcessTree.PID != 0 {
		ruleFailure.SetRuntimeProcessDetails(armotypes.ProcessTree{
			ProcessTree: enrichedEvent.ProcessTree,
			ContainerID: enrichedEvent.ContainerID,
		})
	}

	return ruleFailure
}

func (r *RuleFailureCreator) enrichRuleFailure(ruleFailure *types.GenericRuleFailure) {
	if r.enricher != nil && !reflect.ValueOf(r.enricher).IsNil() {
		if err := r.enricher.EnrichRuleFailure(ruleFailure); err != nil {
			if errors.Is(err, ErrRuleShouldNotBeAlerted) { // TODO: @amitschendel - I think this check doesn't work.
				return
			}
		}
	}
}

func (r *RuleFailureCreator) setProfileMetadata(rule typesv1.Rule, ruleFailure *types.GenericRuleFailure, objectCache objectcache.ObjectCache) {
	triggerEvent := ruleFailure.GetTriggerEvent()
	if triggerEvent == nil {
		return
	}

	var profileType armotypes.ProfileType
	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()
	profileRequirment := rule.ProfileDependency
	if !(profileRequirment == armotypes.Required || profileRequirment == armotypes.Optional) {
		return
	}

	for _, tag := range rule.Tags {
		switch tag {
		case types.ApplicationProfile:
			profileType = armotypes.ApplicationProfile
		case types.NetworkProfile:
			profileType = armotypes.NetworkProfile
		}
	}

	switch profileType {
	case armotypes.ApplicationProfile, armotypes.NetworkProfile:
		state := objectCache.ContainerProfileCache().GetContainerProfileState(triggerEvent.GetContainerID())
		baseRuntimeAlert.ProfileMetadata = buildProfileMetadata(state, profileType, profileRequirment)
	default:
		profileMetadata := &armotypes.ProfileMetadata{
			ProfileDependency: profileRequirment,
			FailOnProfile:     false,
			Error:             fmt.Sprintf("profile type %d not supported", profileRequirment),
		}
		baseRuntimeAlert.ProfileMetadata = profileMetadata
	}
	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)
}

// buildProfileMetadata builds the ProfileMetadata for an ApplicationProfile or
// NetworkProfile alert from a container's profile state. Every current
// GetContainerProfileState implementation never returns nil -- it synthesizes
// an error state when no entry exists yet for this container (any container,
// host included, very early in its lifecycle before a profile has been
// primed) -- but a nil state is still guarded here defensively, since this is
// an interface contract a future or alternate implementation could violate.
// Metadata is always attached so the error signal reaches alert consumers;
// state.Error is surfaced via the Error field rather than gating attachment
// on its absence.
func buildProfileMetadata(state *objectcache.ProfileState, profileType armotypes.ProfileType, profileRequirment armotypes.ProfileDependency) *armotypes.ProfileMetadata {
	if state == nil {
		return &armotypes.ProfileMetadata{
			Type:              profileType,
			ProfileDependency: profileRequirment,
			FailOnProfile:     false,
			Error:             "profile state unavailable",
		}
	}
	profileMetadata := &armotypes.ProfileMetadata{
		Status:            state.Status,
		Completion:        state.Completion,
		Name:              state.Name,
		FailOnProfile:     state.Status == helpersv1.Completed,
		Type:              profileType,
		ProfileDependency: profileRequirment,
	}
	if state.Error != nil {
		profileMetadata.Error = state.Error.Error()
	}
	return profileMetadata
}

func (r *RuleFailureCreator) setCloudServices(ruleFailure *types.GenericRuleFailure) {
	triggerEvent := ruleFailure.GetTriggerEvent()
	if triggerEvent == nil {
		return
	}

	if cloudServices := r.dnsManager.ResolveContainerProcessToCloudServices(triggerEvent.GetContainerID(), ruleFailure.GetBaseRuntimeAlert().InfectedPID); cloudServices != nil {
		ruleFailure.SetCloudServices(cloudServices.ToSlice())
	}

}

func (r *RuleFailureCreator) getHostPath(processTree armotypes.Process, triggerEvent utils.EnrichEvent) (string, error) {
	if processTree.Path == "" {
		path, err := utils.GetPathFromPid(processTree.PID)
		if err != nil {
			return "", err
		}
		return filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", processTree.PID, path)), nil
	}

	pidToUse := processTree.PID
	if triggerEvent != nil {
		if containerPID := r.containerIdToPid.Get(triggerEvent.GetContainerID()); containerPID != 0 {
			pidToUse = containerPID
		}
	}
	return filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", pidToUse, processTree.Path)), nil
}

func (r *RuleFailureCreator) setBaseRuntimeAlert(ruleFailure *types.GenericRuleFailure) {
	triggerEvent := ruleFailure.GetTriggerEvent()
	processTree := ruleFailure.GetRuntimeProcessDetails().ProcessTree

	hostPath, err := r.getHostPath(processTree, triggerEvent)
	if err != nil {
		return
	}

	baseRuntimeAlert := ruleFailure.GetBaseRuntimeAlert()

	if triggerEvent != nil {
		baseRuntimeAlert.Timestamp = time.Unix(0, int64(triggerEvent.GetTimestamp()))
	}
	var size int64
	var regular bool
	if hostPath != "" {
		if identity, isRegular, err := utils.StatFile(hostPath); err == nil {
			size, regular = identity.Size, isRegular
		}
	}

	if baseRuntimeAlert.Size == "" && hostPath != "" && size != 0 {
		baseRuntimeAlert.Size = humanize.Bytes(uint64(size))
	}

	// Only a regular file is opened: opening a FIFO would block this goroutine.
	if regular && size != 0 && size < maxFileSize {
		if baseRuntimeAlert.MD5Hash == "" || baseRuntimeAlert.SHA1Hash == "" {
			containerID := ""
			if triggerEvent != nil {
				containerID = triggerEvent.GetContainerID()
			}
			if hashes := r.fileHashes(hostPath, containerID); hashes != nil {
				baseRuntimeAlert.MD5Hash = hashes.MD5Hash
				baseRuntimeAlert.SHA1Hash = hashes.SHA1Hash
			}
		}
	}

	ruleFailure.SetBaseRuntimeAlert(baseRuntimeAlert)

}

// fileHashes returns the hashes of the file at path, or nil when it cannot be
// hashed. The file is opened once and its identity, size and content all come
// from that descriptor. Hashes are cached per container and file identity, and
// concurrent requests for one entry share one computation. A hash is not cached
// for a file on tmpfs, for a file changed within racyWindow of now, or for a file
// that changed while it was being hashed.
func (r *RuleFailureCreator) fileHashes(path, containerID string) *FileHashCache {
	start := time.Now()
	file, identity, err := utils.OpenRegularFile(path)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	if identity.Size == 0 || identity.Size >= maxFileSize {
		return nil
	}

	key := hashKey{containerID: containerID, file: identity}
	if cached, found := r.hashCache.Get(key); found {
		return cached
	}
	cacheable := utils.IsCacheableFS(file) && start.UnixNano()-identity.CtimeNs >= r.racyWindow.Nanoseconds()

	v, err, _ := r.hashGroup.Do(fmt.Sprintf("%+v", key), func() (any, error) {
		if cached, found := r.hashCache.Get(key); found {
			return cached, nil
		}
		// Read exactly the bytes the identity describes, then check that the
		// file is still the same one.
		sha1hash, md5hash, err := r.calculateHashes(io.LimitReader(file, identity.Size))
		if err != nil {
			return nil, err
		}
		if after, err := utils.IdentityOf(file); err != nil || after != identity {
			return nil, errFileChanged
		}
		hashes := &FileHashCache{SHA1Hash: sha1hash, MD5Hash: md5hash}
		if cacheable {
			r.hashCache.Add(key, hashes)
		}
		return hashes, nil
	})
	if err != nil {
		return nil
	}
	return v.(*FileHashCache)
}

func (r *RuleFailureCreator) setRuntimeAlertK8sDetails(ruleFailure *types.GenericRuleFailure, objectCache objectcache.ObjectCache) {
	runtimek8sdetails := ruleFailure.GetRuntimeAlertK8sDetails()
	triggerEvent := ruleFailure.GetTriggerEvent()
	if triggerEvent == nil {
		return
	}

	if runtimek8sdetails.Image == "" {
		runtimek8sdetails.Image = triggerEvent.GetContainerImage()
	}

	if runtimek8sdetails.ImageDigest == "" {
		runtimek8sdetails.ImageDigest = triggerEvent.GetContainerImageDigest()
	}

	if runtimek8sdetails.Namespace == "" {
		runtimek8sdetails.Namespace = triggerEvent.GetNamespace()
	}

	if runtimek8sdetails.PodName == "" {
		runtimek8sdetails.PodName = triggerEvent.GetPod()
	}

	if runtimek8sdetails.PodNamespace == "" {
		runtimek8sdetails.PodNamespace = triggerEvent.GetNamespace()
	}

	if runtimek8sdetails.ContainerName == "" {
		runtimek8sdetails.ContainerName = triggerEvent.GetContainer()
	}

	if runtimek8sdetails.ContainerID == "" {
		runtimek8sdetails.ContainerID = triggerEvent.GetContainerID()
	}

	if runtimek8sdetails.HostNetwork == nil {
		hostNetwork := triggerEvent.GetHostNetwork()
		runtimek8sdetails.HostNetwork = &hostNetwork
	}

	// Extract pod UID and workload UID
	containerID := runtimek8sdetails.ContainerID
	namespace := runtimek8sdetails.Namespace
	podName := runtimek8sdetails.PodName

	// The host pseudo-container is not backed by a Kubernetes Pod or workload.
	// Its shared container data is synthetic (see pkg/hostidentity), so neither
	// the WorkloadUID it carries nor a pod-cache lookup on its synthetic
	// Namespace/PodName describes real cluster state - leave both UIDs empty
	// rather than fabricating them. This guard is separate from setProfileMetadata's
	// presence-based profile-metadata check (state.Error == nil) - the two functions
	// guard different data (profile metadata vs. K8s pod/workload UIDs).
	if utils.IsHost(containerID) {
		ruleFailure.SetRuntimeAlertK8sDetails(runtimek8sdetails)
		return
	}

	// Try to get WorkloadUID from shared container data (pre-computed from WLID)
	if containerID != "" {
		if sharedData := objectCache.K8sObjectCache().GetSharedContainerData(containerID); sharedData != nil {
			if sharedData.WorkloadUID != "" {
				runtimek8sdetails.WorkloadUID = sharedData.WorkloadUID
			}
		}
	}

	// Get pod UID from pod cache
	if namespace != "" && podName != "" {
		pod := objectCache.K8sObjectCache().GetPod(namespace, podName)
		if pod != nil {
			runtimek8sdetails.PodUID = string(pod.UID)
		}
	}

	ruleFailure.SetRuntimeAlertK8sDetails(runtimek8sdetails)
}

func (r *RuleFailureCreator) setContextSpecificFields(ruleFailure *types.GenericRuleFailure, enrichedEvent *events.EnrichedEvent) {
	// If no source context is available, default to Kubernetes (backward compatible)
	if enrichedEvent.SourceContext == nil {
		ruleFailure.SetSourceContext(contextdetection.Kubernetes)
		return
	}

	sourceContextType := enrichedEvent.SourceContext.Context()
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()

	switch sourceContextType {
	case contextdetection.Kubernetes:
		ruleFailure.SetSourceContext(contextdetection.Kubernetes)
		// K8s alerts use existing K8s details populated by setRuntimeAlertK8sDetails

	case contextdetection.Host:
		ruleFailure.SetSourceContext(contextdetection.Host)
		if k8sDetails.ContainerID == "" {
			k8sDetails.ContainerID = enrichedEvent.ContainerID
		}
		hostname, err := os.Hostname()
		if err == nil {
			k8sDetails.NodeName = hostname
		}

	case contextdetection.Standalone, contextdetection.Container, contextdetection.ECS:
		ruleFailure.SetSourceContext(sourceContextType)
		// For containerized contexts, populate container-specific fields in RuntimeAlertK8sDetails
		if k8sDetails.ContainerID == "" {
			k8sDetails.ContainerID = enrichedEvent.ContainerID
		}

		triggerEvent := ruleFailure.GetTriggerEvent()
		if triggerEvent != nil {
			if k8sDetails.Image == "" {
				k8sDetails.Image = triggerEvent.GetContainerImage()
			}
			// Use container name from trigger event if available
			if k8sDetails.ContainerName == "" {
				k8sDetails.ContainerName = triggerEvent.GetContainer()
			}
		}
	}

	ruleFailure.SetRuntimeAlertK8sDetails(k8sDetails)
}
