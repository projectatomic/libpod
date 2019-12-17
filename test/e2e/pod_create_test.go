package integration

import (
	"os"

	. "github.com/containers/libpod/test/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Podman pod create", func() {
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
		podmanTest.CleanupPod()
		f := CurrentGinkgoTestDescription()
		processTestResult(f)

	})

	It("podman create pod", func() {
		_, ec, podID := podmanTest.CreatePod("")
		Expect(ec).To(Equal(0))

		check := podmanTest.Podman([]string{"pod", "ps", "-q", "--no-trunc"})
		check.WaitWithDefaultTimeout()
		match, _ := check.GrepString(podID)
		Expect(match).To(BeTrue())
		Expect(len(check.OutputToStringArray())).To(Equal(1))
	})

	It("podman create pod with name", func() {
		name := "test"
		_, ec, _ := podmanTest.CreatePod(name)
		Expect(ec).To(Equal(0))

		check := podmanTest.Podman([]string{"pod", "ps", "--no-trunc"})
		check.WaitWithDefaultTimeout()
		match, _ := check.GrepString(name)
		Expect(match).To(BeTrue())
	})

	It("podman create pod with doubled name", func() {
		name := "test"
		_, ec, _ := podmanTest.CreatePod(name)
		Expect(ec).To(Equal(0))

		_, ec2, _ := podmanTest.CreatePod(name)
		Expect(ec2).To(Not(Equal(0)))

		check := podmanTest.Podman([]string{"pod", "ps", "-q"})
		check.WaitWithDefaultTimeout()
		Expect(len(check.OutputToStringArray())).To(Equal(1))
	})

	It("podman create pod with same name as ctr", func() {
		name := "test"
		session := podmanTest.Podman([]string{"create", "--name", name, ALPINE, "ls"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		_, ec, _ := podmanTest.CreatePod(name)
		Expect(ec).To(Not(Equal(0)))

		check := podmanTest.Podman([]string{"pod", "ps", "-q"})
		check.WaitWithDefaultTimeout()
		Expect(len(check.OutputToStringArray())).To(Equal(0))
	})

	It("podman create pod without network portbindings", func() {
		name := "test"
		session := podmanTest.Podman([]string{"pod", "create", "--name", name})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		pod := session.OutputToString()

		webserver := podmanTest.Podman([]string{"run", "--pod", pod, "-dt", nginx})
		webserver.WaitWithDefaultTimeout()
		Expect(webserver.ExitCode()).To(Equal(0))

		check := SystemExec("nc", []string{"-z", "localhost", "80"})
		Expect(check.ExitCode()).To(Equal(1))
	})

	It("podman create pod with network portbindings", func() {
		name := "test"
		session := podmanTest.Podman([]string{"pod", "create", "--name", name, "-p", "8080:80"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
		pod := session.OutputToString()

		webserver := podmanTest.Podman([]string{"run", "--pod", pod, "-dt", nginx})
		webserver.WaitWithDefaultTimeout()
		Expect(webserver.ExitCode()).To(Equal(0))

		check := SystemExec("nc", []string{"-z", "localhost", "8080"})
		Expect(check.ExitCode()).To(Equal(0))
	})

	It("podman create pod with no infra but portbindings should fail", func() {
		name := "test"
		session := podmanTest.Podman([]string{"pod", "create", "--infra=false", "--name", name, "-p", "80:80"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(125))
	})

	It("podman create pod in custom CNI network", func() {
		SkipIfRootless()
		netName := "podmantestnetwork"
		ipAddrPrefix := "10.20.30."
		createNet := podmanTest.Podman([]string{"network", "create", "--subnet", ipAddrPrefix + "0/24", netName})
		createNet.WaitWithDefaultTimeout()
		Expect(createNet.ExitCode()).To(BeZero())

		name := "test"
		create := podmanTest.Podman([]string{"pod", "create", "--name", name, "--network", netName})
		create.WaitWithDefaultTimeout()
		Expect(create.ExitCode()).To(Equal(0))

		run := podmanTest.Podman([]string{"run", "--rm", "--pod", name, ALPINE, "ip", "addr"})
		run.WaitWithDefaultTimeout()
		Expect(run.ExitCode()).To(BeZero())
		Expect(run.OutputToString()).To(ContainSubstring(ipAddrPrefix))

		rmNet := podmanTest.Podman([]string{"network", "rm", "-f", netName})
		rmNet.WaitWithDefaultTimeout()
		Expect(rmNet.ExitCode()).To(BeZero())
	})
})
