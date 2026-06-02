/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Copyright (c) Advanced Micro Devices, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package selinuxpolicy installs a custom SELinux policy module on nodes that
// require it so that the KMM worker process (running as spc_t) can call
// finit_module() on files labelled container_var_lib_t.  This is needed on
// SLES 16.0 where the container-selinux policy does not include the
// "allow spc_t container_var_lib_t:system module_load" rule.
package selinuxpolicy

import (
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	amdv1alpha1 "github.com/ROCm/gpu-operator/api/v1alpha1"
)

const (
	// SELinuxPolicyName is the name suffix appended to DeviceConfig.Name for the DaemonSet.
	SELinuxPolicyName = "selinux-policy"

	// defaultInstallerImage is a minimal image that ships with nsenter(1).
	// Users can override it via devConfig.Spec.CommonConfig.InitContainerImage.
	defaultInstallerImage = "busybox:1.36"

	// policyModuleName is the SELinux module name compiled and installed on the host.
	// It must be stable so the idempotency check (`semodule -l | grep <name>`) works.
	policyModuleName = "kmm-amdgpu-load"

	// installerScript is the shell script executed by the init container.
	// It:
	//   1. Skips gracefully if SELinux is not enforcing on the host.
	//   2. Skips if the policy module is already installed (idempotent).
	//   3. Writes the .te source to a hostPath-mounted /tmp directory so that
	//      the host's /tmp/<dir> is visible when we nsenter the host mount
	//      namespace (PID 1).
	//   4. Uses the host's checkmodule / semodule_package / semodule binaries
	//      via `nsenter -m -t 1 --` to compile and install the module entirely
	//      within the host's mount namespace.
	installerScript = `#!/bin/sh
set -e

POLICY_NAME=` + policyModuleName + `
HOST_WORK_DIR=/host-tmp/kmm-selinux
WORK_DIR=/tmp/kmm-selinux

# Verify SELinux tooling exists on the host.
if ! nsenter -m -t 1 -- sh -c 'test -x /usr/sbin/getenforce' 2>/dev/null; then
    echo "getenforce not found on host; SELinux may not be installed. Skipping."
    exit 0
fi

SELINUX_STATUS=$(nsenter -m -t 1 -- /usr/sbin/getenforce 2>/dev/null || echo "Disabled")
if [ "$SELINUX_STATUS" = "Disabled" ]; then
    echo "SELinux is disabled on the host. Skipping policy installation."
    exit 0
fi

# Idempotency: skip if module already present.
if nsenter -m -t 1 -- /usr/sbin/semodule -l 2>/dev/null | grep -q "^${POLICY_NAME}"; then
    echo "SELinux module '${POLICY_NAME}' is already installed. Nothing to do."
    exit 0
fi

echo "Installing SELinux module '${POLICY_NAME}' ..."

# Write the policy source file to a path shared with the host's /tmp
# via the hostPath volume mounted at /host-tmp inside this container.
mkdir -p "${HOST_WORK_DIR}"
cat > "${HOST_WORK_DIR}/${POLICY_NAME}.te" << 'POLICY_EOF'
module kmm-amdgpu-load 1.0;

require {
    type spc_t;
    type container_var_lib_t;
    class system module_load;
}

# Allow the KMM worker process (spc_t) to call finit_module() on kernel
# module files that reside in an emptyDir volume (container_var_lib_t).
allow spc_t container_var_lib_t:system module_load;
POLICY_EOF

# Compile and install inside the host mount namespace.
nsenter -m -t 1 -- /usr/sbin/checkmodule -M -m \
    -o "${WORK_DIR}/${POLICY_NAME}.mod" \
    "${WORK_DIR}/${POLICY_NAME}.te"

nsenter -m -t 1 -- /usr/sbin/semodule_package \
    -o "${WORK_DIR}/${POLICY_NAME}.pp" \
    -m "${WORK_DIR}/${POLICY_NAME}.mod"

nsenter -m -t 1 -- /usr/sbin/semodule -i "${WORK_DIR}/${POLICY_NAME}.pp"

echo "SELinux module '${POLICY_NAME}' installed successfully."
`
)

//go:generate mockgen -source=selinuxpolicy.go -package=selinuxpolicy -destination=mock_selinuxpolicy.go SELinuxPolicyAPI

// SELinuxPolicyAPI defines the interface for building the SELinux policy installer DaemonSet.
type SELinuxPolicyAPI interface {
	SetSELinuxPolicyInstallerAsDesired(ds *appsv1.DaemonSet, devConfig *amdv1alpha1.DeviceConfig) error
}

type selinuxPolicyInstaller struct {
	scheme *runtime.Scheme
}

// NewSELinuxPolicyInstaller creates a new SELinuxPolicyAPI backed by scheme.
func NewSELinuxPolicyInstaller(scheme *runtime.Scheme) SELinuxPolicyAPI {
	return &selinuxPolicyInstaller{scheme: scheme}
}

// SetSELinuxPolicyInstallerAsDesired mutates ds to match the desired DaemonSet state.
// ds must already have Namespace and Name set by the caller.
func (s *selinuxPolicyInstaller) SetSELinuxPolicyInstallerAsDesired(ds *appsv1.DaemonSet, devConfig *amdv1alpha1.DeviceConfig) error {
	matchLabels := map[string]string{"daemonset-name": ds.Name}

	nodeSelector := map[string]string{}
	for k, v := range devConfig.Spec.Selector {
		nodeSelector[k] = v
	}

	// Inherit the driver tolerations so the installer runs on the same
	// nodes as the KMM worker pods.
	tolerations := []v1.Toleration{}
	if devConfig.Spec.Driver.Tolerations != nil {
		tolerations = append(tolerations, devConfig.Spec.Driver.Tolerations...)
	}

	// Allow operator deployers to override the installer image.
	installerImage := defaultInstallerImage
	if devConfig.Spec.CommonConfig.InitContainerImage != "" {
		installerImage = devConfig.Spec.CommonConfig.InitContainerImage
	}

	imagePullSecrets := []v1.LocalObjectReference{}
	if len(devConfig.Spec.CommonConfig.ImageRegistrySecrets) > 0 {
		imagePullSecrets = append(imagePullSecrets, devConfig.Spec.CommonConfig.ImageRegistrySecrets...)
	}

	gracePeriod := int64(1)
	hostPathType := v1.HostPathDirectoryOrCreate

	ds.Spec = appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: matchLabels},
		Template: v1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: matchLabels,
			},
			Spec: v1.PodSpec{
				// hostPID is required so that nsenter can enter PID 1's namespaces.
				HostPID: true,
				InitContainers: []v1.Container{
					{
						Name:    "selinux-policy-installer",
						Image:   installerImage,
						Command: []string{"sh", "-c", installerScript},
						SecurityContext: &v1.SecurityContext{
							Privileged: ptr.To(true),
						},
						VolumeMounts: []v1.VolumeMount{
							{
								// Host's /tmp is mounted here so files written to
								// /host-tmp/... inside the container appear at /tmp/...
								// in the host mount namespace when we nsenter PID 1.
								Name:      "host-tmp",
								MountPath: "/host-tmp",
							},
						},
					},
				},
				// A pause container keeps the DaemonSet pod alive after the
				// init container completes, preventing constant restarts.
				Containers: []v1.Container{
					{
						Name:    "pause",
						Image:   installerImage,
						Command: []string{"sh", "-c", "while true; do sleep 3600; done"},
						SecurityContext: &v1.SecurityContext{
							Privileged: ptr.To(false),
						},
					},
				},
				PriorityClassName:             "system-node-critical",
				NodeSelector:                  nodeSelector,
				Tolerations:                   tolerations,
				ImagePullSecrets:              imagePullSecrets,
				TerminationGracePeriodSeconds: &gracePeriod,
				Volumes: []v1.Volume{
					{
						Name: "host-tmp",
						VolumeSource: v1.VolumeSource{
							HostPath: &v1.HostPathVolumeSource{
								Path: "/tmp",
								Type: &hostPathType,
							},
						},
					},
				},
			},
		},
	}

	return controllerutil.SetControllerReference(devConfig, ds, s.scheme)
}
