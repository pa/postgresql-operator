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

package controller

import (
	"context"
	"log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	postgresqlpramodhayyappandevv1alpha1 "github.com/pa/postgresql-operator.git/api/v1alpha1"
	"github.com/pa/postgresql-operator.git/internal/common"
)

var _ = Describe("Role Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "testresource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		role := &postgresqlpramodhayyappandevv1alpha1.Role{}
		connSecret := &corev1.Secret{}
		roleSecret := &corev1.Secret{}

		BeforeEach(func() {
			By("creating the connection secret resource for the Kind Role")
			connSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "db-conn-secret", Namespace: "default"},
				Data:       map[string][]byte{common.ResourceCredentialsSecretConnectionStringKey: []byte("postgres://postgres:YFRYVNh4qk@my-postgresql.default.svc.cluster.local:5432/postgres")},
			}
			Expect(k8sClient.Create(ctx, connSecret)).To(Succeed())

			By("creating the role password secret resource for the Kind Role")
			roleSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "role-password", Namespace: "default"},
				Data:       map[string][]byte{"password": []byte("securepassword")},
			}
			Expect(k8sClient.Create(ctx, roleSecret)).To(Succeed())

			By("creating the custom resource for the Kind Role")
			err := k8sClient.Get(ctx, typeNamespacedName, role)
			if err != nil && errors.IsNotFound(err) {
				resource := &postgresqlpramodhayyappandevv1alpha1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: postgresqlpramodhayyappandevv1alpha1.RoleSpec{
						ConnectSecretRef: common.SecretKeySelector{
							ResourceReference: common.ResourceReference{
								Name:      "db-conn-secret",
								Namespace: "default",
							},
							Key: "connectionString",
						},
						PasswordSecretRef: common.SecretKeySelector{
							ResourceReference: common.ResourceReference{
								Name:      "role-password",
								Namespace: "default",
							},
							Key: "password",
						},
						Options: postgresqlpramodhayyappandevv1alpha1.RoleOptions{
							SuperUser:       true,
							Inherit:         true,
							ConnectionLimit: 100,
							ValidUntil:      "May 4 12:00:00 2015 +1",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			err := k8sClient.Get(ctx, typeNamespacedName, role)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Role")
			Expect(k8sClient.Delete(ctx, role)).To(Succeed())

			// Reconcile as the resource has finalizers
			controllerReconciler := &RoleReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			By("Cleanup the specific connection secret")
			Expect(k8sClient.Delete(ctx, connSecret)).To(Succeed())

			By("Cleanup the specific role password secret")
			Expect(k8sClient.Delete(ctx, roleSecret)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("First - Reconciling the created resource")
			controllerReconciler := &RoleReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			Expect(err).NotTo(HaveOccurred())

			By("Updating the role password secret resource for the Kind Role")
			roleSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "role-password", Namespace: "default"},
				Data:       map[string][]byte{"password": []byte("differentPassword")},
			}
			Expect(k8sClient.Update(ctx, roleSecret)).To(Succeed())

			By("Second - Reconciling the created resource")

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			Expect(err).NotTo(HaveOccurred())

			k8sClient.Get(ctx, typeNamespacedName, role)
			log.Default().Printf("Status Conditions - %v", role.Status.Conditions)

			Expect(err).Should(HaveOccurred())
		})
	})
})
