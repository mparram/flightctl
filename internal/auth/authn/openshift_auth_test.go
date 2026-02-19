package authn

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/flightctl/flightctl/api/v1beta1"
	"github.com/flightctl/flightctl/pkg/k8sclient"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOpenShiftAuth_GetRolesForUserInProject_IncludesGroupSubjects(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockK8s := k8sclient.NewMockK8SClient(ctrl)
	mockK8s.EXPECT().
		ListRoleBindings(gomock.Any(), "team-one").
		Return(&rbacv1.RoleBindingList{
			Items: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-one"},
					RoleRef:    rbacv1.RoleRef{Name: api.ExternalRoleViewer},
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "alice"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-one"},
					RoleRef:    rbacv1.RoleRef{Name: api.ExternalRoleViewer},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "dev-team"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-one"},
					RoleRef:    rbacv1.RoleRef{Name: api.ExternalRoleOperator},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "dev-team"},
					},
				},
			},
		}, nil)

	auth := &OpenShiftAuth{
		spec:      api.OpenShiftProviderSpec{},
		k8sClient: mockK8s,
		log:       logrus.New(),
	}

	roles, err := auth.getRolesForUserInProject(context.Background(), "team-one", "alice", []string{"dev-team"})
	require.NoError(t, err)
	assert.Equal(t, []string{api.ExternalRoleOperator, api.ExternalRoleViewer}, roles)
}

func TestOpenShiftAuth_GetRolesForUserInProject_WithoutGroupsKeepsUserBehavior(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockK8s := k8sclient.NewMockK8SClient(ctrl)
	mockK8s.EXPECT().
		ListRoleBindings(gomock.Any(), "team-one").
		Return(&rbacv1.RoleBindingList{
			Items: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-one"},
					RoleRef:    rbacv1.RoleRef{Name: api.ExternalRoleViewer},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "dev-team"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "team-one"},
					RoleRef:    rbacv1.RoleRef{Name: api.ExternalRoleInstaller},
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "alice"},
					},
				},
			},
		}, nil)

	auth := &OpenShiftAuth{
		spec:      api.OpenShiftProviderSpec{},
		k8sClient: mockK8s,
		log:       logrus.New(),
	}

	roles, err := auth.getRolesForUserInProject(context.Background(), "team-one", "alice", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{api.ExternalRoleInstaller}, roles)
}

func TestOpenShiftAuth_GetOpenShiftGroupsForUser(t *testing.T) {
	var authHeader string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		assert.Equal(t, "/apis/user.openshift.io/v1/groups", r.URL.Path)
		_, _ = w.Write([]byte(`{
			"items":[
				{"metadata":{"name":"RedHat"},"users":["user01"]},
				{"metadata":{"name":"qa-team"},"users":["other-user"]},
				{"metadata":{"name":"dev-team"},"users":["user01","user02"]}
			]
		}`))
	}))
	defer server.Close()

	auth := &OpenShiftAuth{
		spec: api.OpenShiftProviderSpec{
			ClusterControlPlaneUrl: &server.URL,
		},
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
		log: logrus.New(),
	}

	groups, err := auth.getOpenShiftGroupsForUserWithToken(context.Background(), "user01", "sa-token-123")
	require.NoError(t, err)
	assert.Equal(t, "Bearer sa-token-123", authHeader)
	assert.Equal(t, []string{"RedHat", "dev-team"}, groups)
}
