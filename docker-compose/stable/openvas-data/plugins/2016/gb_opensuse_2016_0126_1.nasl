# Copyright (C) 2016 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851188");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2016-02-02 17:17:07 +0100 (Tue, 02 Feb 2016)");
  script_cve_id("CVE-2015-5307", "CVE-2015-7504", "CVE-2015-7549", "CVE-2015-8339",
                "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8345", "CVE-2015-8504",
                "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8558",
                "CVE-2015-8567", "CVE-2015-8568");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2016:0126-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  - CVE-2015-8567, CVE-2015-8568: xen: qemu: net: vmxnet3: host memory
  leakage (boo#959387)

  - CVE-2015-8550: xen: paravirtualized drivers incautious about shared
  memory contents (XSA-155, boo#957988)

  - CVE-2015-8558: xen: qemu: usb: infinite loop in ehci_advance_state
  results in DoS (boo#959006)

  - CVE-2015-7549: xen: qemu pci: null pointer dereference issue (boo#958918)

  - CVE-2015-8504: xen: qemu: ui: vnc: avoid floating point exception
  (boo#958493)

  - CVE-2015-8554: xen: qemu-dm buffer overrun in MSI-X handling (XSA-164,
  boo#958007)

  - CVE-2015-8555: xen: information leak in legacy x86 FPU/XMM
  initialization (XSA-165, boo#958009)

  - boo#958523: xen: ioreq handling possibly susceptible to multiple read
  issue (XSA-166)

  - CVE-2015-8345: xen: qemu: net: eepro100: infinite loop in processing
  command block list (boo#956832)

  - CVE-2015-5307: xen: x86: CPU lockup during fault delivery (XSA-156,
  boo#954018)

  - boo#956592: xen: virtual PMU is unsupported (XSA-163)

  - CVE-2015-8339, CVE-2015-8340: xen: XENMEM_exchange error handling issues
  (XSA-159, boo#956408)

  - CVE-2015-8341: xen: libxl leak of pv kernel and initrd on error
  (XSA-160, boo#956409)

  - CVE-2015-7504: xen: heap buffer overflow vulnerability in pcnet emulator
  (XSA-162, boo#956411)");

  script_tag(name:"affected", value:"xen on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0126-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.5.2_04_k4.1.13_5~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.5.2_04_k4.1.13_5~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.5.2_04~9.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
