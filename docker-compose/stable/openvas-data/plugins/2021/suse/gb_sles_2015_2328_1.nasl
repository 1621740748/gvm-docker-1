# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2328.1");
  script_cve_id("CVE-2015-5307", "CVE-2015-7311", "CVE-2015-7504", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8345");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2328-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2328-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152328-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:2328-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:
- bsc#956832 - CVE-2015-8345: xen: qemu: net: eepro100: infinite loop in
 processing command block list
- bsc#956592 - xen: virtual PMU is unsupported (XSA-163)
- bsc#956408 - CVE-2015-8339, CVE-2015-8340: xen: XENMEM_exchange error
 handling issues (XSA-159)
- bsc#956409 - CVE-2015-8341: xen: libxl leak of pv kernel and initrd on
 error (XSA-160)
- bsc#956411 - CVE-2015-7504: xen: heap buffer overflow vulnerability in
 pcnet emulator (XSA-162)
- bsc#947165 - CVE-2015-7311: xen: libxl fails to honour readonly flag on
 disks with qemu-xen (xsa-142)
- bsc#954405 - CVE-2015-8104: Xen: guest to host DoS by triggering an
 infinite loop in microcode via #DB exception
- bsc#954018 - CVE-2015-5307: xen: x86: CPU lockup during fault delivery
 (XSA-156) CVE-2015-5307-xsa156.patch
- bsc#950704 - CVE-2015-7970: xen: x86: Long latency populate-on-demand
 operation is not preemptible (XSA-150)
 563212c9-x86-PoD-Eager-sweep-for-zeroed-pages.patch
- bsc#951845 - CVE-2015-7972: xen: x86: populate-on-demand balloon size
 inaccuracy can crash guests (XSA-153) xsa153-libxl.patch
 xend-xsa153.patch
- Drop 5604f239-x86-PV-properly-populate-descriptor-tables.patch
- bsc#950703 - CVE-2015-7969: xen: leak of main per-domain vcpu pointer
 array (DoS) (XSA-149)
- bsc#950705 - CVE-2015-7969: xen: x86: leak of per-domain
 profiling-related vcpu pointer array (DoS) (XSA-151)
- bsc#950706 - CVE-2015-7971: xen: x86: some pmu and profiling hypercalls
 log without rate limiting (XSA-152)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.3_06_k3.12.48_52.27~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.3_06_k3.12.48_52.27~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.3_06~22.15.1", rls:"SLES12.0"))) {
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
