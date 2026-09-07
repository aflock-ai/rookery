// jade:ring local
package auth

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func privateStateDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir
}

func TestExplicitStateDirectoryStoresOnlyDedicatedCredentials(t *testing.T) {
	dir := privateStateDirectory(t)
	t.Setenv("CILOCK_STATE_DIR", dir)
	t.Setenv("JUDGE_SHARED_SESSION", "true")
	old := doMigrateLegacy
	doMigrateLegacy = func() error { t.Fatal("isolated state attempted ambient migration"); return nil }
	t.Cleanup(func() { doMigrateLegacy = old })
	resetMigrateOnceForTest()
	t.Cleanup(resetMigrateOnceForTest)

	path, err := StorePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "credentials.json"), path)
	agentPath, err := AgentStorePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "agent-credentials.json"), agentPath)
	platform := "https://isolated.example.test"
	require.NoError(t, Save(Credential{PlatformURL: platform, Token: "synthetic-session", ExpiresAt: time.Now().Add(time.Hour)}))
	got, err := Lookup(platform)
	require.NoError(t, err)
	require.Equal(t, "synthetic-session", got.Token)
	pending := AgentCredential{PlatformURL: platform, TenantID: "tenant-test", AgentID: "agent-test", RefreshCredential: "synthetic-refresh"}
	require.NoError(t, SavePendingAgent(pending))
	before, err := LookupAgent(platform)
	require.NoError(t, err)
	require.Nil(t, before, "delivery does not itself activate the agent")
	require.NoError(t, PromotePendingAgentIf(pending))
	agent, err := LookupAgent(platform)
	require.NoError(t, err)
	require.Equal(t, "agent-test", agent.AgentID)
	binary, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(binary, "-test.run=^TestExplicitStateDirectoryChildRead$")
	child.Env = append(os.Environ(), "CILOCK_STATE_TEST_CHILD=1")
	output, err := child.CombinedOutput()
	require.NoError(t, err, "%s", output)
	for _, file := range []string{path, agentPath} {
		info, err := os.Stat(file)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	other := privateStateDirectory(t)
	t.Setenv("CILOCK_STATE_DIR", other)
	missing, err := Lookup(platform)
	require.NoError(t, err)
	require.Nil(t, missing)
	missingAgent, err := LookupAgent(platform)
	require.NoError(t, err)
	require.Nil(t, missingAgent)
}

func TestExplicitStateDirectoryChildRead(t *testing.T) {
	if os.Getenv("CILOCK_STATE_TEST_CHILD") != "1" {
		t.Skip("only the synthetic parent fixture invokes the child")
	}
	path, err := AgentStorePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(os.Getenv("CILOCK_STATE_DIR"), "agent-credentials.json"), path)
	agent, err := LookupAgent("https://isolated.example.test")
	require.NoError(t, err)
	require.NotNil(t, agent)
	require.Equal(t, "agent-test", agent.AgentID)
}

func TestExplicitStateDirectoryRefusesInvalidPathsWithoutFallback(t *testing.T) {
	old := doMigrateLegacy
	doMigrateLegacy = func() error { t.Fatal("invalid isolated state attempted ambient migration"); return nil }
	t.Cleanup(func() { doMigrateLegacy = old })
	resetMigrateOnceForTest()
	t.Cleanup(resetMigrateOnceForTest)
	root := privateStateDirectory(t)
	public := filepath.Join(root, "public")
	require.NoError(t, os.Mkdir(public, 0o755))
	file := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(file, []byte("not a directory"), 0o600))
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(root, link))
	for _, value := range []string{"", "relative", root + "\n", root + "\t", public, file, link, filepath.Join(link, "child"), filepath.Join(root, "missing")} {
		t.Run(filepath.Base(value), func(t *testing.T) {
			t.Setenv("CILOCK_STATE_DIR", value)
			t.Setenv("JUDGE_SHARED_SESSION", "true")
			require.False(t, useShared())
			_, err := StorePath()
			require.Error(t, err)
			_, err = AgentStorePath()
			require.Error(t, err)
			_, err = Lookup("https://isolated.example.test")
			require.Error(t, err)
			require.Error(t, Save(Credential{PlatformURL: "https://isolated.example.test"}))
		})
	}
}

func TestExplicitStateDirectoryIgnoresCompletedAmbientMigration(t *testing.T) {
	t.Setenv("CILOCK_STATE_DIR", privateStateDirectory(t))
	t.Setenv("JUDGE_SHARED_SESSION", "true")
	migrated.Store(true)
	t.Cleanup(resetMigrateOnceForTest)
	require.False(t, useShared(), "a previous migration does not override explicit state")
}

func TestExplicitStateDirectoryNeverReadsJctlHome(t *testing.T) {
	for _, value := range []string{"", "relative", privateStateDirectory(t)} {
		t.Run(filepath.Base(value), func(t *testing.T) {
			t.Setenv("CILOCK_STATE_DIR", value)
			credential, ok := lookupJctlWithHome("https://isolated.example.test", func() (string, error) {
				t.Fatal("explicit state tried to discover the ambient jctl home")
				return "", nil
			})
			require.False(t, ok)
			require.Nil(t, credential)
		})
	}
}

func TestDefaultStateDirectoryPreservesPathsAndJctlReadthrough(t *testing.T) {
	// Restore the caller's setting without redirecting HOME or its credential stores.
	t.Setenv("CILOCK_STATE_DIR", "")
	require.NoError(t, os.Unsetenv("CILOCK_STATE_DIR"))
	base, err := os.UserConfigDir()
	require.NoError(t, err)
	path, err := StorePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "cilock", "credentials.json"), path)
	agentPath, err := AgentStorePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "cilock", "agent-credentials.json"), agentPath)
	fixture := privateStateDirectory(t)
	require.NoError(t, os.Mkdir(filepath.Join(fixture, ".jctl"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(fixture, ".jctl", "config.yaml"), []byte("contexts:\n  test:\n    judgeURL: https://isolated.example.test\n    token: synthetic-jctl-session\n"), 0o600))
	credential, ok := lookupJctlWithHome("https://isolated.example.test", func() (string, error) { return fixture, nil })
	require.True(t, ok)
	require.Equal(t, "synthetic-jctl-session", credential.Token)
}
