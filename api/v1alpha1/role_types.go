/*
Copyright 2025.

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

package v1alpha1

import (
	"github.com/pa/postgresql-operator.git/internal/common"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RoleOptions struct {
	// SuperUser grants SUPERUSER privilege when true.
	// +optional
	SuperUser bool `json:"superUser,omitempty"`

	// Inherit grants INHERIT privilege when true.
	// +optional
	Inherit bool `json:"inherit,omitempty"`

	// CreateRole grants CREATEROLE privilege when true.
	// +optional
	CreateRole bool `json:"createRole,omitempty"`

	// CreateDB grants CREATEDB privilege when true.
	// +optional
	CreateDB bool `json:"createDB,omitempty"`

	// CanLogin grants LOGIN privilege when true.
	// +optional
	CanLogin bool `json:"canLogin,omitempty"`

	// Replication grants REPLICATION privilege when true.
	// +optional
	Replication bool `json:"replication,omitempty"`

	// ConnectionLimit sets CONNECTION LIMIT.
	// +optional
	ConnectionLimit int32 `json:"connectionLimit,omitempty"`

	// ValidUntil sets VALID UNTIL.
	// +optional
	ValidUntil string `json:"validUntil"`

	// BypassRLS grants BYPASSRLS privilege when true.
	// +optional
	BypassRLS bool `json:"bypassRLS,omitempty"`
}

// RoleConfigurationParameter is a role configuration parameter.
type RoleConfigurationParameter struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// RoleSpec defines the desired state of Role
type RoleSpec struct {
	// ConnectSecretRef references the secret that contains the database connection details used
	// for this role.
	// +required
	ConnectSecretRef common.SecretKeySelector `json:"connectSecretRef"`

	// PasswordSecretRef references the secret that contains the password used
	// for this role. If no reference is given, a password will be auto-generated.
	// +required
	PasswordSecretRef common.SecretKeySelector `json:"passwordSecretRef"`

	// Privileges to be granted.
	// +optional
	Options RoleOptions `json:"options,omitempty"`

	// ConfigurationParameters to be applied to the role. If specified, any other configuration parameters set on the
	// role in the database will be reset.
	//
	// See https://www.postgresql.org/docs/current/runtime-config-client.html for some available configuration parameters.
	// +optional
	ConfigurationParameters *[]RoleConfigurationParameter `json:"configurationParameters,omitempty"`
}

// RoleStatus defines the observed state of Role
type RoleStatus struct {
	Conditions []metav1.Condition `json:"conditions"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Role is the Schema for the roles API
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[-1:].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[-1:].reason`
// +kubebuilder:printcolumn:name="Message",type=string,priority=1,JSONPath=`.status.conditions[-1:].message`
// +kubebuilder:printcolumn:name="Last Transition Time",type=string,priority=1,JSONPath=`.status.conditions[-1:].lastTransitionTime`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoleSpec   `json:"spec"`
	Status RoleStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// RoleList contains a list of Role
type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Role `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Role{}, &RoleList{})
}
