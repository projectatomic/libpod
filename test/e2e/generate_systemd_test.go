package integration

import (
	"io/ioutil"
	"os"

	. "github.com/containers/podman/v2/test/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Podman generate systemd", func() {
	var (
		tempdir    string
		err        error
		podmanTest *PodmanTestIntegration
	)

	BeforeEach(func() {
		tempdir, err = CreateTempDirInTempDir()
		if err != nil {
			os.Exit(1)
		}
		podmanTest = PodmanTestCreate(tempdir)
		podmanTest.Setup()
		podmanTest.SeedImages()
	})

	AfterEach(func() {
		podmanTest.Cleanup()
		f := CurrentGinkgoTestDescription()
		processTestResult(f)

	})

	It("podman generate systemd on bogus container/pod", func() {
		session := podmanTest.Podman([]string{"generate", "systemd", "foobar"})
		session.WaitWithDefaultTimeout()
		Expect(session).To(ExitWithError())
	})

	It("podman generate systemd bad restart policy", func() {
		session := podmanTest.Podman([]string{"generate", "systemd", "--restart-policy", "never", "foobar"})
		session.WaitWithDefaultTimeout()
		Expect(session).To(ExitWithError())
	})

	It("podman generate systemd bad timeout value", func() {
		session := podmanTest.Podman([]string{"generate", "systemd", "--time", "-1", "foobar"})
		session.WaitWithDefaultTimeout()
		Expect(session).To(ExitWithError())
	})

	It("podman generate systemd bad restart-policy value", func() {
		session := podmanTest.Podman([]string{"create", "--name", "foobar", "alpine", "top"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"generate", "systemd", "--restart-policy", "bogus", "foobar"})
		session.WaitWithDefaultTimeout()
		Expect(session).To(ExitWithError())
		Expect(session.ErrorToString()).To(ContainSubstring("bogus is not a valid restart policy"))
	})

	It("podman generate systemd good timeout value", func() {
		session := podmanTest.Podman([]string{"create", "--name", "foobar", "alpine", "top"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"generate", "systemd", "--time", "1234", "foobar"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		Expect(session.OutputToString()).To(ContainSubstring("TimeoutStopSec=1294"))
		Expect(session.OutputToString()).To(ContainSubstring(" stop -t 1234 "))
	})

	It("podman generate systemd", func() {
		n := podmanTest.Podman([]string{"run", "--name", "nginx", "-dt", nginx})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "nginx"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// The podman commands in the unit should not contain the root flags
		Expect(session.OutputToString()).ToNot(ContainSubstring(" --runroot"))
	})

	It("podman generate systemd --files --name", func() {
		n := podmanTest.Podman([]string{"run", "--name", "nginx", "-dt", nginx})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--files", "--name", "nginx"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		for _, file := range session.OutputToStringArray() {
			os.Remove(file)
		}
		Expect(session.OutputToString()).To(ContainSubstring("/container-nginx.service"))
	})

	It("podman generate systemd with timeout", func() {
		n := podmanTest.Podman([]string{"run", "--name", "nginx", "-dt", nginx})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--time", "5", "nginx"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		Expect(session.OutputToString()).To(ContainSubstring("podman stop -t 5"))
	})

	It("podman generate systemd pod --name", func() {
		n := podmanTest.Podman([]string{"pod", "create", "--name", "foo"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-1", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-2", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--time", "42", "--name", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# pod-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("Requires=container-foo-1.service container-foo-2.service"))
		Expect(session.OutputToString()).To(ContainSubstring("# container-foo-1.service"))
		Expect(session.OutputToString()).To(ContainSubstring(" start foo-1"))
		Expect(session.OutputToString()).To(ContainSubstring("-infra")) // infra container
		Expect(session.OutputToString()).To(ContainSubstring("# container-foo-2.service"))
		Expect(session.OutputToString()).To(ContainSubstring(" stop -t 42 foo-2"))
		Expect(session.OutputToString()).To(ContainSubstring("BindsTo=pod-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("PIDFile="))
		Expect(session.OutputToString()).To(ContainSubstring("/userdata/conmon.pid"))

		// The podman commands in the unit should not contain the root flags
		Expect(session.OutputToString()).ToNot(ContainSubstring(" --runroot"))
	})

	It("podman generate systemd pod --name --files", func() {
		n := podmanTest.Podman([]string{"pod", "create", "--name", "foo"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-1", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--name", "--files", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		for _, file := range session.OutputToStringArray() {
			os.Remove(file)
		}

		Expect(session.OutputToString()).To(ContainSubstring("/pod-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("/container-foo-1.service"))
	})

	It("podman generate systemd --new --name foo", func() {
		n := podmanTest.Podman([]string{"create", "--name", "foo", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "-t", "42", "--name", "--new", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# container-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring(" --replace "))
		Expect(session.OutputToString()).To(ContainSubstring(" stop --ignore --cidfile %t/container-foo.ctr-id -t 42"))
		if !IsRemote() {
			// The podman commands in the unit should contain the root flags if generate systemd --new is used
			Expect(session.OutputToString()).To(ContainSubstring(" --runroot"))
		}
	})

	It("podman generate systemd --new --name=foo", func() {
		n := podmanTest.Podman([]string{"create", "--name=foo", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "-t", "42", "--name", "--new", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# container-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring(" --replace "))
		Expect(session.OutputToString()).To(ContainSubstring(" stop --ignore --cidfile %t/container-foo.ctr-id -t 42"))
	})

	It("podman generate systemd --new without explicit detaching param", func() {
		n := podmanTest.Podman([]string{"create", "--name", "foo", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--timeout", "42", "--name", "--new", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("--cgroups=no-conmon -d"))
	})

	It("podman generate systemd --new with explicit detaching param in middle", func() {
		n := podmanTest.Podman([]string{"create", "--name", "foo", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--time", "42", "--name", "--new", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("--name foo alpine top"))
	})

	It("podman generate systemd --new pod", func() {
		n := podmanTest.Podman([]string{"pod", "create", "--name", "foo"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--time", "42", "--name", "--new", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
	})

	It("podman generate systemd --container-prefix con", func() {
		n := podmanTest.Podman([]string{"create", "--name", "foo", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--name", "--container-prefix", "con", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# con-foo.service"))

	})

	It("podman generate systemd --separator _", func() {
		n := podmanTest.Podman([]string{"create", "--name", "foo", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--name", "--separator", "_", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# container_foo.service"))
	})

	It("podman generate systemd pod --pod-prefix p", func() {
		n := podmanTest.Podman([]string{"pod", "create", "--name", "foo"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-1", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-2", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--pod-prefix", "p", "--name", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# p-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("Requires=container-foo-1.service container-foo-2.service"))
		Expect(session.OutputToString()).To(ContainSubstring("# container-foo-1.service"))
		Expect(session.OutputToString()).To(ContainSubstring("BindsTo=p-foo.service"))
	})

	It("podman generate systemd pod --pod-prefix p --container-prefix con --separator _ change all prefixes/separator", func() {
		n := podmanTest.Podman([]string{"pod", "create", "--name", "foo"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-1", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-2", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--container-prefix", "con", "--pod-prefix", "p", "--separator", "_", "--name", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# p_foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("Requires=con_foo-1.service con_foo-2.service"))
		Expect(session.OutputToString()).To(ContainSubstring("# con_foo-1.service"))
		Expect(session.OutputToString()).To(ContainSubstring("# con_foo-2.service"))
		Expect(session.OutputToString()).To(ContainSubstring("BindsTo=p_foo.service"))
	})

	It("podman generate systemd pod with containers --new", func() {
		tmpDir, err := ioutil.TempDir("", "")
		Expect(err).To(BeNil())
		tmpFile := tmpDir + "podID"
		defer os.RemoveAll(tmpDir)

		n := podmanTest.Podman([]string{"pod", "create", "--pod-id-file", tmpFile, "--name", "foo"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-1", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		n = podmanTest.Podman([]string{"create", "--pod", "foo", "--name", "foo-2", "alpine", "top"})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--new", "--name", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		// Grepping the output (in addition to unit tests)
		Expect(session.OutputToString()).To(ContainSubstring("# pod-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("Requires=container-foo-1.service container-foo-2.service"))
		Expect(session.OutputToString()).To(ContainSubstring("BindsTo=pod-foo.service"))
		Expect(session.OutputToString()).To(ContainSubstring("pod create --infra-conmon-pidfile %t/pod-foo.pid --pod-id-file %t/pod-foo.pod-id --name foo"))
		Expect(session.OutputToString()).To(ContainSubstring("ExecStartPre=/bin/rm -f %t/pod-foo.pid %t/pod-foo.pod-id"))
		Expect(session.OutputToString()).To(ContainSubstring("pod stop --ignore --pod-id-file %t/pod-foo.pod-id -t 10"))
		Expect(session.OutputToString()).To(ContainSubstring("pod rm --ignore -f --pod-id-file %t/pod-foo.pod-id"))
	})

	It("podman generate systemd --format json", func() {
		n := podmanTest.Podman([]string{"create", "--name", "foo", ALPINE})
		n.WaitWithDefaultTimeout()
		Expect(n.ExitCode()).To(Equal(0))

		session := podmanTest.Podman([]string{"generate", "systemd", "--format", "json", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		Expect(session.IsJSONOutputValid()).To(BeTrue())
	})

	It("podman generate systemd --new create command with double curly braces", func() {
		// Regression test for #9034
		session := podmanTest.Podman([]string{"create", "--name", "foo", "--log-driver=journald", "--log-opt=tag={{.Name}}", ALPINE})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"generate", "systemd", "--new", "foo"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		Expect(session.OutputToString()).To(ContainSubstring(" --log-opt=tag={{.Name}} "))

		session = podmanTest.Podman([]string{"pod", "create", "--name", "pod", "--label", "key={{someval}}"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"generate", "systemd", "--new", "pod"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		Expect(session.OutputToString()).To(ContainSubstring(" --label key={{someval}}"))
	})
})
