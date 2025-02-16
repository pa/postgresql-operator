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
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	postgresql "github.com/pa/postgresql-operator.git/api/v1alpha1"
	"github.com/pa/postgresql-operator.git/internal/common"
	"github.com/pa/postgresql-operator.git/internal/repository"
)

const (
	roleFinalizer           = "role.postgresql.pramodhayyappan.dev/finalizer"
	passwordSecretNameField = ".spec.passwordSecretRef.name"
	connectSecretNameField  = ".spec.connectSecretRef.name"
	ROLECREATED             = "RoleCreated"
	ROLEEXISTS              = "RoleExists"
	ROLESYNCED              = "RoleSynced"
	ROLEPASSWORDSYNCED      = "RolePasswordSynced"
	ROLECREATEFAILED        = "RoleCreateFailed"
	ROLESYNCFAILED          = "RoleSyncFailed"
	ROLEPASSWORDSYNCFAILED  = "RolePasswordSyncFailed"
	ROLEDELETED             = "RoleDeleted"
	ROLEDELETEFAILED        = "RoleDeleteFailed"
	ROLEGETFAILED           = "RoleGetFailed"
)

// RoleReconciler reconciles a Role object
type RoleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	logger logr.Logger
}

//+kubebuilder:rbac:groups=postgresql.pramodhayyappan.dev,resources=roles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=postgresql.pramodhayyappan.dev,resources=roles/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=postgresql.pramodhayyappan.dev,resources=roles/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Role object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.3/pkg/reconcile
func (r *RoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.logger = log.FromContext(ctx)

	// Get reconcile time
	roleReconcileTime, err := time.ParseDuration(flag.Lookup("reconcile-period").Value.String())
	if err != nil {
		panic(err)
	}

	role := &postgresql.Role{}
	err = r.Get(ctx, req.NamespacedName, role)
	if err != nil {
		return ctrl.Result{}, nil
	}

	// Get Database connection secret
	connectionSecret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Namespace: role.Spec.ConnectSecretRef.Namespace,
		Name:      role.Spec.ConnectSecretRef.Name,
	}, connectionSecret)
	if err != nil {
		reason := fmt.Sprintf(
			"Failed to get connection secret `%s/%s` for role `%s`",
			role.Spec.ConnectSecretRef.Name,
			role.Spec.ConnectSecretRef.Namespace,
			role.Name,
		)

		r.appendRoleStatusCondition(ctx, role, common.FAIL, metav1.ConditionFalse, common.RESOURCENOTFOUND, err.Error())
		r.logger.Error(err, reason)
		return ctrl.Result{}, nil
	}

	// Get Role password secret
	passwordSecret := &corev1.Secret{}
	err = r.Get(
		ctx, types.NamespacedName{
			Namespace: role.Spec.PasswordSecretRef.Namespace,
			Name:      role.Spec.PasswordSecretRef.Name,
		},
		passwordSecret,
	)
	if err != nil {
		reason := fmt.Sprintf(
			"Failed to get password secret `%s/%s` for role `%s`",
			role.Spec.PasswordSecretRef.Name,
			role.Spec.PasswordSecretRef.Namespace,
			role.Name,
		)
		r.appendRoleStatusCondition(ctx, role, common.FAIL, metav1.ConditionFalse, common.RESOURCENOTFOUND, err.Error())
		r.logger.Error(err, reason)
		return ctrl.Result{}, nil
	}

	// Role Password
	rolePassword := string(passwordSecret.Data[role.Spec.PasswordSecretRef.Key])

	// Check if Role Password secret value is empty
	if len(strings.TrimSpace(rolePassword)) <= 0 {
		message := fmt.Sprintf(
			"The value for required key `%s` in secret `%s/%s` should not be empty or null.",
			role.Spec.PasswordSecretRef.Key,
			role.Spec.PasswordSecretRef.Namespace,
			role.Spec.PasswordSecretRef.Name,
		)
		r.appendRoleStatusCondition(ctx, role, common.FAIL, metav1.ConditionFalse, common.RESOURCENOTFOUND, message)
		r.logger.Error(errors.New(message), "Please update the role password in secret with right values")
		return ctrl.Result{}, nil
	}

	// Connect to Database
	conn, err := pgx.Connect(context.Background(), string(connectionSecret.Data[common.ResourceCredentialsSecretConnectionStringKey]))
	if err != nil {
		message := fmt.Sprintf(
			"Cannot connect to dataase, check if required keys `%s` in secret `%s/%s` should not be empty or null.",
			common.ResourceCredentialsSecretConnectionStringKey,
			role.Spec.ConnectSecretRef.Namespace,
			role.Spec.ConnectSecretRef.Name,
		)
		r.appendRoleStatusCondition(ctx, role, common.FAIL, metav1.ConditionFalse, common.CONNECTIONFAILED, message)
		r.logger.Error(errors.New(message), "Please update the keys in secret with right values")
		return ctrl.Result{}, nil
	}
	defer conn.Close(ctx)

	// Add finalizers to handle delete scenario
	if role.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(role, roleFinalizer) {
			controllerutil.AddFinalizer(role, roleFinalizer)
			err = r.Update(ctx, role)
			if err != nil {
				return ctrl.Result{}, nil
			}
		}
	} else {
		if controllerutil.ContainsFinalizer(role, roleFinalizer) {
			r.DeletRole(ctx, conn, role)
			controllerutil.RemoveFinalizer(role, roleFinalizer)
			err := r.Update(ctx, role)
			if err != nil {
				return ctrl.Result{}, nil
			}
		}
		return ctrl.Result{}, nil
	}

	// Initialize repository object
	repo := repository.New(conn)

	if role.Generation == 2 {
		// Check if role exists
		row, _ := repo.GetRoleByName(ctx, pgtype.Text{String: role.Name, Valid: true})
		// Delete role if already exists
		if row.Rolname.Valid {
			r.DeletRole(ctx, conn, role)
		}
		typeName, status, reason, message := r.CreateRole(ctx, conn, role, rolePassword)
		r.appendRoleStatusCondition(ctx, role, typeName, status, reason, message)
	} else {
		isPasswordSync, isRoleInSync, err := r.ObserveRoleState(ctx, repo, role, rolePassword)
		if err != nil {
			r.appendRoleStatusCondition(ctx, role, common.FAIL, metav1.ConditionFalse, "ObserveStateFailure", err.Error())
		}
		if !isPasswordSync || !isRoleInSync {
			typeName, status, reason, message := r.SyncRole(ctx, conn, role, rolePassword, !isPasswordSync)
			r.appendRoleStatusCondition(ctx, role, typeName, status, reason, message)
		}
	}

	// TODO: Support for Configuration Parameter

	return ctrl.Result{RequeueAfter: roleReconcileTime}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleReconciler) SetupWithManager(mgr ctrl.Manager) error {

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &postgresql.Role{}, passwordSecretNameField, func(rawObj client.Object) []string {
		// Extract the Secret name from the Role Spec,
		role := rawObj.(*postgresql.Role)
		if role.Spec.PasswordSecretRef.Name == "" {
			return nil
		}
		return []string{role.Spec.PasswordSecretRef.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&postgresql.Role{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, secret client.Object) []ctrl.Request {
			// map a change from referenced secret to PasswordSecretRef, which causes its re-reconcile
			roleList := &postgresql.RoleList{}
			if err := mgr.GetClient().List(ctx, roleList); err != nil {
				mgr.GetLogger().Error(err, "while listing PasswordSecretRef")
				return nil
			}

			reqs := make([]ctrl.Request, 0, len(roleList.Items))
			for _, item := range roleList.Items {
				if item.Spec.PasswordSecretRef.Name == secret.GetName() {
					reqs = append(reqs, ctrl.Request{
						NamespacedName: types.NamespacedName{
							Namespace: item.GetNamespace(),
							Name:      item.GetName(),
						},
					})
				}
			}

			return reqs
		})).
		Complete(r)
}

func (r *RoleReconciler) appendRoleStatusCondition(ctx context.Context, role *postgresql.Role, typeName string, status metav1.ConditionStatus, reason string, message string) {
	time := metav1.Time{Time: time.Now()}
	condition := metav1.Condition{Type: typeName, Status: status, Reason: reason, Message: message, LastTransitionTime: time}

	roleStatusConditions := role.Status.Conditions

	if len(roleStatusConditions) > 0 {
		// Only keep 5 statuses
		if len(roleStatusConditions) >= 5 {
			roleStatusConditions = roleStatusConditions[len(roleStatusConditions)-5:]
		}

		lastCondition := &roleStatusConditions[len(roleStatusConditions)-1]
		if lastCondition.Reason != condition.Reason {
			role.Status.Conditions = append(roleStatusConditions, condition)
			if err := r.Status().Update(ctx, role); err != nil {
				r.logger.Error(err, fmt.Sprintf("Resource status update failed for role `%s`", role.Name))
			}
		}
	} else {
		role.Status.Conditions = append(roleStatusConditions, condition)
		if err := r.Status().Update(ctx, role); err != nil {
			r.logger.Error(err, fmt.Sprintf("Resource status update failed for role `%s`", role.Name))
		}
	}
}

func negateClause(clause string, negate *bool, out *[]string) {
	// If clause boolean is not set (nil pointer), do not push a setting.
	// This means the postgres default is applied.
	if negate == nil {
		return
	}

	if !(*negate) {
		clause = "NO" + clause
	}
	*out = append(*out, clause)
}

func optionsToClauses(ro postgresql.RoleOptions) []string {
	// Never copy user inputted data to this string. These values are
	// passed directly into the query.
	roc := []string{}

	negateClause("SUPERUSER", &ro.SuperUser, &roc)
	negateClause("INHERIT", &ro.Inherit, &roc)
	negateClause("CREATEDB", &ro.CreateDB, &roc)
	negateClause("CREATEROLE", &ro.CreateRole, &roc)
	negateClause("LOGIN", &ro.CanLogin, &roc)
	negateClause("REPLICATION", &ro.Replication, &roc)
	negateClause("BYPASSRLS", &ro.BypassRLS, &roc)

	if ro.ConnectionLimit > 0 {
		connectionLimit := fmt.Sprintf("CONNECTION LIMIT %d", ro.ConnectionLimit)
		roc = append(roc, connectionLimit)
	}
	if len(ro.ValidUntil) > 0 {
		validUntil := fmt.Sprintf("VALID UNTIL '%s'", ro.ValidUntil)
		roc = append(roc, validUntil)
	}

	return roc
}

func (r *RoleReconciler) CreateRole(ctx context.Context, conn *pgx.Conn, role *postgresql.Role, rolePassword string) (string, metav1.ConditionStatus, string, string) {
	options := strings.Join(optionsToClauses(role.Spec.Options), " ")
	_, err := conn.Exec(ctx, fmt.Sprintf("CREATE ROLE \"%s\" WITH PASSWORD '%s' %s", role.Name, rolePassword, options))
	if err != nil {
		message := fmt.Sprintf("Failed to create Role `%s`.", role.Name)
		r.logger.Error(err, message)
		return common.FAIL, metav1.ConditionFalse, ROLECREATEFAILED, message
	}

	message := fmt.Sprintf("Role `%s` got created successfully", role.Name)
	r.logger.Info(message)
	return common.CREATE, metav1.ConditionTrue, ROLECREATED, message
}

func (r *RoleReconciler) DeletRole(ctx context.Context, conn *pgx.Conn, role *postgresql.Role) (string, metav1.ConditionStatus, string, string) {
	_, err := conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS \"%s\"", role.Name))
	if err != nil {
		message := fmt.Sprintf("Failed to drop Role `%s`.", role.Name)
		r.logger.Error(err, message)
		return common.FAIL, metav1.ConditionFalse, ROLEDELETEFAILED, message
	}

	message := fmt.Sprintf("Role `%s` got dropped successfully", role.Name)
	r.logger.Info(message)
	return common.DELETE, metav1.ConditionTrue, ROLEDELETED, message
}

func (r *RoleReconciler) SyncRole(ctx context.Context, conn *pgx.Conn, role *postgresql.Role, rolePassword string, isPasswordSync bool) (string, metav1.ConditionStatus, string, string) {
	options := strings.Join(optionsToClauses(role.Spec.Options), " ")
	_, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE \"%s\" WITH PASSWORD '%s' %s", role.Name, rolePassword, options))
	if err != nil {
		if isPasswordSync {
			message := fmt.Sprintf("Failed to sync Role `%s` with password", role.Name)
			r.logger.Info(message)
			return common.SYNC, metav1.ConditionFalse, ROLEPASSWORDSYNCFAILED, message
		}
		message := fmt.Sprintf("Failed to sync Role `%s`.", role.Name)
		r.logger.Error(err, message)
		return common.FAIL, metav1.ConditionFalse, ROLESYNCFAILED, message
	}

	if isPasswordSync {
		message := fmt.Sprintf("Role `%s` got synced successfully with password", role.Name)
		r.logger.Info(message)
		return common.SYNC, metav1.ConditionTrue, ROLEPASSWORDSYNCED, message
	}
	message := fmt.Sprintf("Role `%s` got synced successfully", role.Name)
	r.logger.Info(message)
	return common.SYNC, metav1.ConditionTrue, ROLESYNCED, message
}

func (r *RoleReconciler) ObserveRoleState(ctx context.Context, repo *repository.Queries, role *postgresql.Role, rolePassword string) (bool, bool, error) {
	// Although using the standard library would have been an option, sqlc does not support overrides for roles, hence the use of pgtype.
	isRoleInSync, err := repo.IsRoleInSync(ctx, repository.IsRoleInSyncParams{
		Rolname: pgtype.Text{
			String: role.Name,
			Valid:  true,
		},
		Rolsuper: pgtype.Bool{
			Bool:  role.Spec.Options.SuperUser,
			Valid: true,
		},
		Rolinherit: pgtype.Bool{
			Bool:  role.Spec.Options.Inherit,
			Valid: true,
		},
		Rolcreaterole: pgtype.Bool{
			Bool:  role.Spec.Options.CreateRole,
			Valid: true,
		},
		Rolcreatedb: pgtype.Bool{
			Bool:  role.Spec.Options.CreateDB,
			Valid: true,
		},
		Rolcanlogin: pgtype.Bool{
			Bool:  role.Spec.Options.CanLogin,
			Valid: true,
		},
		Rolreplication: pgtype.Bool{
			Bool:  role.Spec.Options.Replication,
			Valid: true,
		},
		Rolconnlimit: pgtype.Int4{
			Int32: role.Spec.Options.ConnectionLimit,
			Valid: true,
		},
		Rolbypassrls: pgtype.Bool{
			Bool:  role.Spec.Options.BypassRLS,
			Valid: true,
		},
	})
	if err != nil {
		return false, false, err
	}

	isPasswordSync := false

	hash, err := repo.GetRolePasswordHash(ctx, role.Name)
	if err != nil {
		return false, false, err
	}

	hashString := hash.String

	// Determine authentication method and verify password
	switch {
	case strings.HasPrefix(hashString, "md5"):
		isPasswordSync = common.VerifyMD5(rolePassword, role.Name, hashString)

	case strings.HasPrefix(hashString, "SCRAM-SHA-256"):
		isPasswordSync = common.VerifySCRAM(rolePassword, hashString)

	default:
		r.logger.Error(errors.New("unknown password hashing method for this role"), "Role", "name", role.Name)
	}
	return isPasswordSync, isRoleInSync, nil
}
